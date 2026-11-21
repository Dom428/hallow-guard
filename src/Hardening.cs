// Hallow Guard v1.6 - Windows hardening checks, all read-only:
//  - Microsoft Defender's settings (MSFT_MpPreference): PUA protection, cloud-delivered protection, automatic sample submission,
//    network protection, how many Attack Surface Reduction rules are on;
//  - Defender's exclusions (paths, extensions, processes) - broad ones and ones pointing at unsigned or Temp files are flagged.
//    Windows only shows them to administrators: then "Check (admin)" reads them through UAC (it only reads, like BitLocker's check);
//  - remote access: Remote Desktop and Network Level Authentication (registry), remote-access tools installed / running / starting
//    with Windows (uninstall entries, services, Run keys, the process list); Hallow Assist is covered by its own family check;
//  - old or risky features: SMBv1 (Win32_OptionalFeature, else the registry), the PowerShell 2.0 engine, AutoPlay for USB drives;
//  - accounts: local accounts Windows marks as not needing a password, Guest, more than one admin, you as admin with UAC on "never notify";
//  - Wi-Fi: saved networks that are open (no password) and connect by themselves, and the security of the network you're on.
//    netsh is only ever asked "wlan show profiles", "wlan show profile name=..." and "wlan show interfaces" - never with key=clear:
//    Wi-Fi passwords are never read, shown or logged (SafeNetsh refuses any "key=" argument, and drops any key line it might get).
// Nothing here changes a setting: buttons open the right Windows Security / Settings page or show the steps.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace HallowGuard
{
    // ---------------- what the checks look at (null = couldn't be read)
    public class DefenderPrefs
    {
        public bool Read;
        public int? Pua, Maps, Samples, NetProt;          // PUAProtection 0/1/2, MAPSReporting 0/1/2, SubmitSamplesConsent 0-3, EnableNetworkProtection 0/1/2
        public int AsrRules, AsrOn, AsrAudit, AsrWarn;    // ASR rules configured / blocking / audit / warn
        public List<string> ExPaths = new List<string>(), ExExts = new List<string>(), ExProcs = new List<string>();
        public bool ExHidden;                             // "N/A: Must be an administrator to view exclusions"
        public bool ExFromAdminCheck; public DateTime? ExCheckedAt;
    }
    public class RemoteTool
    {
        public string Name; public bool Installed, Running, AutoStart, Service;
        public bool Unattended { get { return Service && AutoStart; } }   // starts as a service with Windows: reachable without anyone clicking
    }
    public class LocalAccount
    {
        public string Name, Sid; public bool Disabled, PasswordRequired = true, Admin;
        public bool IsGuest { get { return Sid != null && Sid.EndsWith("-501"); } }
        public bool IsBuiltInAdmin { get { return Sid != null && Sid.EndsWith("-500"); } }
        public bool IsSystemOnly { get { return Sid != null && (Sid.EndsWith("-503") || Sid.EndsWith("-504")); } }   // DefaultAccount, WDAGUtilityAccount
    }
    public class WifiProfile { public string Name, Auth, Cipher; public bool AutoConnect, Open, Weak; }
    public class ExclusionItem { public string Kind, Value, Flag; }   // Kind: path | extension | process; Flag: why it's risky (null = fine)

    public class HardeningFacts
    {
        public DefenderPrefs Mp = new DefenderPrefs();
        public bool? Rdp, Nla;
        public bool ToolsRead; public List<RemoteTool> Tools = new List<RemoteTool>();
        public bool? Smb1, Ps2, AutoPlay; public string Smb1How;
        public bool AccountsRead; public List<LocalAccount> Accounts = new List<LocalAccount>(); public string CurrentUser; public bool? CurrentIsAdmin;
        public bool WifiRead, NoWifi; public List<WifiProfile> Wifi = new List<WifiProfile>();
        public string WifiConnected, WifiConnectedAuth, WifiConnectedCipher;   // null name = not connected
        public List<ExclusionItem> Exclusions = new List<ExclusionItem>();
        public List<string> Timings = new List<string>();
        public DateTime When = DateTime.Now;
    }

    // ---------------- the data sources (the real PC, or fakes in the tests)
    public interface IMpPrefSource { Dictionary<string, object> Read(); }
    public interface IReg { object Get(string key, string name); string[] SubKeys(string key); string[] ValueNames(string key); }
    public interface INetsh { string Run(string args); }
    public interface IAccountSource { List<LocalAccount> Read(); }
    public interface IProcSource { List<string> Names(); }
    public interface IFeatureSource { Dictionary<string, int> Read(string[] names); }   // name -> InstallState (1 = enabled); missing = not part of this Windows; null = couldn't read
    public interface IHardeningSource { HardeningFacts Read(); }

    // netsh is only asked to show things - and never for a Wi-Fi key
    public class SafeNetsh : INetsh
    {
        readonly INetsh inner;
        public SafeNetsh(INetsh inner) { this.inner = inner; }
        public static bool Allowed(string args)
        {
            if (args == null) return false;
            var a = args.Trim().ToLowerInvariant();
            if (a.Contains("key=") || a.Contains("key =") || a.Contains(" key ")) return false;
            return a == "wlan show profiles" || a == "wlan show interfaces" || (a.StartsWith("wlan show profile name=\"") && a.EndsWith("\"") && a.Count(ch => ch == '"') == 2);
        }
        public string Run(string args)
        {
            if (!Allowed(args)) throw new InvalidOperationException("netsh: only wlan show profiles / profile name=... / interfaces are allowed (never key=clear)");
            var o = inner.Run(args) ?? "";
            return string.Join("\n", o.Replace("\r\n", "\n").Split('\n').Where(l => l.IndexOf("Key Content", StringComparison.OrdinalIgnoreCase) < 0));
        }
    }

    public class HardeningEnv
    {
        public IMpPrefSource Mp; public IReg Reg; public INetsh Netsh; public IAccountSource Accounts; public IProcSource Procs; public IFeatureSource Features;
        public string CurrentUser; public PathRoots Roots; public Func<string, bool> FileExists; public Func<string, string> Signer; public Func<string, string> Expand;
        public string ExclusionsFile;   // what "Check (admin)" wrote (trusted for 7 days)
        public Func<DateTime> Now = () => DateTime.Now;

        public static HardeningEnv Real()
        {
            return new HardeningEnv
            {
                Mp = new WmiMpPrefs(), Reg = new RealReg(), Netsh = new RealNetsh(), Accounts = new WmiAccounts(), Procs = new RealProcs(), Features = new WmiFeatures(),
                CurrentUser = Environment.UserName, Roots = PathRoots.Current(), FileExists = File.Exists, Signer = Signing.Signer, Expand = Environment.ExpandEnvironmentVariables,
                ExclusionsFile = HardeningProbe.ExclusionsFile
            };
        }
    }
    public class WindowsHardening : IHardeningSource { public HardeningFacts Read() { return HardeningProbe.Read(HardeningEnv.Real()); } }
    public class FakeHardeningSource : IHardeningSource { public HardeningFacts Read() { return FakeHardening.Sample(); } }

    public static class HardeningProbe
    {
        public static string ExclusionsFile { get { return Path.Combine(GuardSettings.Dir, "exclusions.json"); } }
        const string Uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", Run = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

        public static HardeningFacts Read(HardeningEnv e)
        {
            var f = new HardeningFacts { When = e.Now() };
            Timed(f, "defender", () => Defender(f, e));
            Timed(f, "remote desktop", () => Rdp(f, e));
            Timed(f, "remote tools", () => Tools(f, e));
            Timed(f, "features", () => Features(f, e));
            Timed(f, "accounts", () => Accounts(f, e));
            Timed(f, "wi-fi", () => Wifi(f, e));
            return f;
        }
        static void Timed(HardeningFacts f, string what, Action a)
        {
            var sw = Stopwatch.StartNew();
            try { a(); } catch { }
            f.Timings.Add(what + " " + sw.ElapsedMilliseconds + " ms");
        }

        // ---- Defender
        static List<string> Strings(object v, ref bool hidden)
        {
            var l = new List<string>();
            if (v is string) v = new[] { (string)v };
            var arr = v as System.Collections.IEnumerable; if (arr == null) return l;
            foreach (var x in arr)
            {
                var s = x as string; if (string.IsNullOrWhiteSpace(s)) continue;
                if (s.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)) { hidden = true; continue; }
                if (!l.Contains(s.Trim(), StringComparer.OrdinalIgnoreCase)) l.Add(s.Trim());
            }
            return l;
        }
        static int? Int(Dictionary<string, object> d, string k) { object v; try { return d.TryGetValue(k, out v) && v != null ? (int?)Convert.ToInt32(v, CultureInfo.InvariantCulture) : null; } catch { return null; } }
        public static DefenderPrefs FromPreference(Dictionary<string, object> d)
        {
            var p = new DefenderPrefs();
            if (d == null) return p;
            p.Read = true;
            p.Pua = Int(d, "PUAProtection"); p.Maps = Int(d, "MAPSReporting"); p.Samples = Int(d, "SubmitSamplesConsent"); p.NetProt = Int(d, "EnableNetworkProtection");
            object ids, acts; bool h = false;
            var idl = d.TryGetValue("AttackSurfaceReductionRules_Ids", out ids) ? Strings(ids, ref h) : new List<string>();
            var al = new List<int>();
            if (d.TryGetValue("AttackSurfaceReductionRules_Actions", out acts) && acts is System.Collections.IEnumerable && !(acts is string))
                foreach (var x in (System.Collections.IEnumerable)acts) { try { al.Add(Convert.ToInt32(x, CultureInfo.InvariantCulture)); } catch { al.Add(0); } }
            p.AsrRules = idl.Count;
            for (int i = 0; i < idl.Count; i++) { int a = i < al.Count ? al[i] : 0; if (a == 1) p.AsrOn++; else if (a == 2) p.AsrAudit++; else if (a == 6) p.AsrWarn++; }
            bool hidden = false; object v;
            p.ExPaths = d.TryGetValue("ExclusionPath", out v) ? Strings(v, ref hidden) : new List<string>();
            p.ExExts = d.TryGetValue("ExclusionExtension", out v) ? Strings(v, ref hidden) : new List<string>();
            p.ExProcs = d.TryGetValue("ExclusionProcess", out v) ? Strings(v, ref hidden) : new List<string>();
            p.ExHidden = hidden;
            return p;
        }
        static void Defender(HardeningFacts f, HardeningEnv e)
        {
            Dictionary<string, object> d = null; try { d = e.Mp.Read(); } catch { }
            f.Mp = FromPreference(d);
            // the lists are admin-only: use what "Check (admin)" read, if it's recent
            if (f.Mp.Read && f.Mp.ExHidden && e.ExclusionsFile != null)
                try
                {
                    if (File.Exists(e.ExclusionsFile) && (e.Now() - File.GetLastWriteTime(e.ExclusionsFile)).TotalDays < 7)
                    {
                        var j = J.Parse(File.ReadAllText(e.ExclusionsFile));
                        if (j != null && j.ContainsKey("paths"))
                        {
                            bool h = false;
                            f.Mp.ExPaths = Strings(J.Get(j, "paths"), ref h); f.Mp.ExExts = Strings(J.Get(j, "exts"), ref h); f.Mp.ExProcs = Strings(J.Get(j, "procs"), ref h);
                            if (!h) { f.Mp.ExHidden = false; f.Mp.ExFromAdminCheck = true; f.Mp.ExCheckedAt = File.GetLastWriteTime(e.ExclusionsFile); }
                        }
                    }
                }
                catch { }
            if (!f.Mp.ExHidden) f.Exclusions = ClassifyAll(f.Mp, e.Roots, e.FileExists, e.Signer, e.Expand);
        }

        // ---- exclusions: broad ones, and ones that point at Temp or at unsigned files
        static readonly string[] RiskyExts = { "exe", "dll", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "scr", "msi", "com", "hta", "lnk", "jar", "pif", "cpl", "sys" };
        static bool Same(string a, string b) { return !string.IsNullOrEmpty(a) && !string.IsNullOrEmpty(b) && string.Equals(a.TrimEnd('\\'), b.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase); }
        static bool Under(string p, string root) { return !string.IsNullOrEmpty(p) && !string.IsNullOrEmpty(root) && p.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase); }
        public static List<ExclusionItem> ClassifyAll(DefenderPrefs p, PathRoots r, Func<string, bool> exists, Func<string, string> signer, Func<string, string> expand)
        {
            var l = new List<ExclusionItem>();
            foreach (var x in p.ExPaths) l.Add(new ExclusionItem { Kind = "path", Value = x, Flag = PathFlag(x, r, exists, signer, expand, false) });
            foreach (var x in p.ExExts) l.Add(new ExclusionItem { Kind = "extension", Value = x, Flag = ExtFlag(x) });
            foreach (var x in p.ExProcs) l.Add(new ExclusionItem { Kind = "process", Value = x, Flag = PathFlag(x, r, exists, signer, expand, true) });
            return l;
        }
        public static string ExtFlag(string ext)
        {
            var e = (ext ?? "").Trim().TrimStart('*').TrimStart('.').ToLowerInvariant();
            if (e == "" || e == "*") return "every file type";
            return RiskyExts.Contains(e) ? "every ." + e + " file" : null;
        }
        public static string PathFlag(string raw, PathRoots r, Func<string, bool> exists, Func<string, string> signer, Func<string, string> expand, bool process)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var p = raw.Trim();
            try { if (expand != null) p = expand(p); } catch { }
            var trimmed = p.TrimEnd('\\', '*').TrimEnd('\\');
            if (p == "*" || p == "*.*" || Regex.IsMatch(p, @"^\*\.(exe|dll|com|scr)$", RegexOptions.IgnoreCase)) return process ? "every program" : "every file";
            if (Regex.IsMatch(trimmed, @"^[A-Za-z]:$") || Regex.IsMatch(p, @"^[A-Za-z]:\\?\*?$")) return "a whole drive";
            if (Regex.IsMatch(p, @"(^|\\)\*\.(exe|dll|ps1|bat|cmd|vbs|js|scr|msi)$", RegexOptions.IgnoreCase)) return "every program in a folder";
            if (r != null)
            {
                var winTemp = r.Windows == null ? null : Path.Combine(r.Windows, "Temp");
                if (Same(trimmed, r.Temp) || Same(trimmed, winTemp) || raw.Trim().TrimEnd('\\').Equals("%TEMP%", StringComparison.OrdinalIgnoreCase) || raw.Trim().TrimEnd('\\').Equals("%TMP%", StringComparison.OrdinalIgnoreCase)) return "the whole Temp folder";
                var appData = r.Roaming == null ? null : Path.GetDirectoryName(r.Roaming.TrimEnd('\\'));   // ...\AppData
                if (Same(trimmed, appData) || Same(trimmed, r.Roaming) || Same(trimmed, r.Local) || (appData != null && Same(trimmed, Path.Combine(appData, "LocalLow")))) return "all of AppData";
                if (Same(trimmed, r.Downloads)) return "the whole Downloads folder";
                var profile = appData == null ? null : Path.GetDirectoryName(appData);
                if (Same(trimmed, profile)) return "your whole user folder";
                if (profile != null && Same(trimmed, Path.GetDirectoryName(profile))) return "every user's folder";
                if (Same(trimmed, r.Windows)) return "the whole Windows folder";
                if (Under(trimmed, r.Temp) || Under(trimmed, winTemp) || trimmed.IndexOf("\\Temp\\", StringComparison.OrdinalIgnoreCase) >= 0 || trimmed.EndsWith("\\Temp", StringComparison.OrdinalIgnoreCase)) return "inside Temp";
            }
            // a program file: unsigned is a red flag (a process exclusion by bare name can't be checked)
            bool isFile = Regex.IsMatch(trimmed, @"\.(exe|dll|scr|com|ps1|bat|cmd|vbs|js|msi|sys)$", RegexOptions.IgnoreCase) && trimmed.IndexOf('\\') >= 0;
            if (isFile)
            {
                bool there = false; try { there = exists != null && exists(trimmed); } catch { }
                if (there) { string s = null; try { s = signer == null ? null : signer(trimmed); } catch { } if (s == null) return "an unsigned file"; }
                else if (r != null && Classifier.RiskyPlace(trimmed, r) != null) return "a missing file in " + Classifier.RiskyPlace(trimmed, r);
                if (r != null && Classifier.RiskyPlace(trimmed, r) == "Downloads") return "a file in Downloads";
            }
            return null;
        }

        // ---- Remote Desktop
        static void Rdp(HardeningFacts f, HardeningEnv e)
        {
            var deny = Dword(e.Reg, @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
            var pol = Dword(e.Reg, @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "fDenyTSConnections");
            if (pol != null) deny = pol;
            f.Rdp = deny == null ? (bool?)null : deny.Value == 0;
            var nla = Dword(e.Reg, @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
            var npol = Dword(e.Reg, @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication");
            if (npol != null) nla = npol;
            f.Nla = nla == null ? (bool?)null : nla.Value != 0;
        }
        public static int? Dword(IReg reg, string key, string name)
        {
            try { var v = reg.Get(key, name); return v == null ? (int?)null : Convert.ToInt32(v, CultureInfo.InvariantCulture); } catch { return null; }
        }

        // ---- remote-access tools: { name, uninstall DisplayName contains..., service names (a trailing * = prefix), process names }
        public static readonly string[][][] Known = {
            new[] { new[] { "AnyDesk" }, new[] { "AnyDesk" }, new[] { "AnyDesk*" }, new[] { "AnyDesk" } },
            new[] { new[] { "TeamViewer" }, new[] { "TeamViewer" }, new[] { "TeamViewer*" }, new[] { "TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64" } },
            new[] { new[] { "RustDesk" }, new[] { "RustDesk" }, new[] { "RustDesk" }, new[] { "rustdesk" } },
            new[] { new[] { "Chrome Remote Desktop" }, new[] { "Chrome Remote Desktop Host" }, new[] { "chromoting" }, new[] { "remoting_host" } },
            new[] { new[] { "Splashtop" }, new[] { "Splashtop Streamer" }, new[] { "SplashtopRemoteService" }, new[] { "SRService", "SRManager", "SRServer" } },
            new[] { new[] { "Parsec" }, new[] { "Parsec" }, new[] { "Parsec" }, new[] { "parsecd" } },
            new[] { new[] { "ScreenConnect (ConnectWise)" }, new[] { "ScreenConnect Client", "ConnectWise Control Client" }, new[] { "ScreenConnect Client*" }, new[] { "ScreenConnect.ClientService", "ScreenConnect.WindowsClient" } },
            new[] { new[] { "LogMeIn" }, new[] { "LogMeIn" }, new[] { "LogMeIn", "LMIGuardianSvc" }, new[] { "LogMeIn", "LMIGuardianSvc" } },
            new[] { new[] { "UltraViewer" }, new[] { "UltraViewer" }, new[] { "UltraViewService" }, new[] { "UltraViewer_Desktop", "UltraViewer_Service" } },
            new[] { new[] { "Supremo" }, new[] { "Supremo" }, new[] { "SupremoService" }, new[] { "Supremo", "SupremoService" } },
            new[] { new[] { "Zoho Assist" }, new[] { "Zoho Assist" }, new[] { "ZohoAssist*" }, new[] { "ZA_Connect", "ZohoURS" } },
            new[] { new[] { "DWService" }, new[] { "DWAgent" }, new[] { "DWAgent" }, new[] { "dwagent", "dwagsvc" } },
            new[] { new[] { "TightVNC" }, new[] { "TightVNC" }, new[] { "tvnserver" }, new[] { "tvnserver" } },
            new[] { new[] { "RealVNC" }, new[] { "VNC Server", "RealVNC" }, new[] { "vncserver" }, new[] { "vncserver" } },
            new[] { new[] { "UltraVNC" }, new[] { "UltraVNC" }, new[] { "uvnc_service" }, new[] { "winvnc" } },
            new[] { new[] { "NoMachine" }, new[] { "NoMachine" }, new[] { "nxservice" }, new[] { "nxservice", "nxnode" } },
            new[] { new[] { "Ammyy Admin" }, new string[0], new string[0], new[] { "AA_v3", "Ammyy_Admin" } },
        };
        static bool NameMatch(string name, string pat)
        {
            if (pat.EndsWith("*")) return name.StartsWith(pat.TrimEnd('*'), StringComparison.OrdinalIgnoreCase);
            return string.Equals(name, pat, StringComparison.OrdinalIgnoreCase);
        }
        static void Tools(HardeningFacts f, HardeningEnv e)
        {
            var display = new List<string>();
            foreach (var root in new[] { @"HKLM\" + Uninstall, @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", @"HKCU\" + Uninstall })
                foreach (var k in Safe(() => e.Reg.SubKeys(root)))
                { var dn = Safe(() => e.Reg.Get(root + "\\" + k, "DisplayName")) as string; if (!string.IsNullOrEmpty(dn)) display.Add(dn); }
            var services = Safe(() => e.Reg.SubKeys(@"HKLM\SYSTEM\CurrentControlSet\Services")).ToList();
            var runs = new List<string>();
            foreach (var root in new[] { @"HKLM\" + Run, @"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"HKCU\" + Run })
                foreach (var v in Safe(() => e.Reg.ValueNames(root))) { var d = Safe(() => e.Reg.Get(root, v)) as string; runs.Add(v + " " + (d ?? "")); }
            var procs = new HashSet<string>(Safe(() => e.Procs.Names().ToArray()), StringComparer.OrdinalIgnoreCase);
            foreach (var t in Known)
            {
                var tool = new RemoteTool { Name = t[0][0] };
                tool.Installed = display.Any(d => t[1].Any(p => d.IndexOf(p, StringComparison.OrdinalIgnoreCase) >= 0) && d.IndexOf("Hallow", StringComparison.OrdinalIgnoreCase) < 0);
                foreach (var s in services.Where(s => t[2].Any(p => NameMatch(s, p))))
                {
                    tool.Installed = true; tool.Service = true;
                    var st = Dword(e.Reg, @"HKLM\SYSTEM\CurrentControlSet\Services\" + s, "Start");
                    if (st == 2) tool.AutoStart = true;   // 2 = automatic (a delayed start is automatic too)
                }
                if (runs.Any(r => t[3].Any(p => Regex.IsMatch(r, @"(^|[\\/""\s])" + Regex.Escape(p) + @"(\.exe)?([""\s]|$)", RegexOptions.IgnoreCase)))) { tool.Installed = true; tool.AutoStart = true; }
                tool.Running = t[3].Any(p => procs.Contains(p));
                if (tool.Installed || tool.Running) f.Tools.Add(tool);
            }
            f.ToolsRead = true;
        }
        static T[] Safe<T>(Func<T[]> a) { try { return a() ?? new T[0]; } catch { return new T[0]; } }
        static object Safe(Func<object> a) { try { return a(); } catch { return null; } }

        // ---- SMBv1, PowerShell 2.0, AutoPlay
        public const string Smb1Feature = "SMB1Protocol", Ps2Feature = "MicrosoftWindowsPowerShellV2Root";
        static void Features(HardeningFacts f, HardeningEnv e)
        {
            Dictionary<string, int> feats = null; try { feats = e.Features.Read(new[] { Smb1Feature, Ps2Feature }); } catch { }
            int st;
            if (feats != null && feats.TryGetValue(Smb1Feature, out st)) { f.Smb1 = st == 1; f.Smb1How = "Windows features"; }
            else
            {
                // the registry: the SMBv1 client driver (mrxsmb10) and the server's SMB1 switch
                var client = Dword(e.Reg, @"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start");
                var server = Dword(e.Reg, @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
                if ((client != null && client != 4) || server == 1) f.Smb1 = true;
                else if (feats != null || client == 4 || client == null) f.Smb1 = false;
                f.Smb1How = "registry";
            }
            if (feats != null) f.Ps2 = feats.TryGetValue(Ps2Feature, out st) && st == 1;   // not listed = removed from this Windows
            // AutoPlay: your own switch, or a policy that turns it off for every drive type
            var dis = Dword(e.Reg, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers", "DisableAutoplay");
            var polU = Dword(e.Reg, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
            var polM = Dword(e.Reg, @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
            bool offByPolicy = (polU != null && (polU.Value & 0x04) != 0 && polU.Value >= 0xFF) || (polM != null && (polM.Value & 0x04) != 0 && polM.Value >= 0xFF);
            f.AutoPlay = !(dis == 1 || offByPolicy);
        }

        // ---- accounts
        static void Accounts(HardeningFacts f, HardeningEnv e)
        {
            f.CurrentUser = e.CurrentUser;
            var l = e.Accounts.Read(); if (l == null) return;
            f.Accounts = l; f.AccountsRead = true;
            var me = l.FirstOrDefault(a => string.Equals(a.Name, e.CurrentUser, StringComparison.OrdinalIgnoreCase));
            f.CurrentIsAdmin = me == null ? (bool?)null : me.Admin;
        }

        // ---- Wi-Fi (never key=clear)
        static void Wifi(HardeningFacts f, HardeningEnv e)
        {
            var sh = new SafeNetsh(e.Netsh);
            var list = sh.Run("wlan show profiles");
            if (NoWlan(list)) { f.NoWifi = true; f.WifiRead = true; return; }
            foreach (var name in ProfileNames(list))
            {
                if (name.IndexOf('"') >= 0) continue;
                var p = ParseProfile(name, sh.Run("wlan show profile name=\"" + name + "\""));
                if (p != null) f.Wifi.Add(p);
            }
            var itf = ParseInterfaces(sh.Run("wlan show interfaces"));
            if (itf != null) { f.WifiConnected = itf[0]; f.WifiConnectedAuth = itf[1]; f.WifiConnectedCipher = itf[2]; }
            f.WifiRead = true;
        }
        static readonly Regex Kv = new Regex(@"^\s*([^:]+?)\s*:\s?(.*)$");
        public static bool NoWlan(string o)
        {
            if (string.IsNullOrWhiteSpace(o)) return true;
            return o.IndexOf("wlansvc", StringComparison.OrdinalIgnoreCase) >= 0 || o.IndexOf("no wireless interface", StringComparison.OrdinalIgnoreCase) >= 0
                || o.IndexOf("There is no wireless", StringComparison.OrdinalIgnoreCase) >= 0;
        }
        public static List<string> ProfileNames(string o)
        {
            var l = new List<string>();
            foreach (var line in (o ?? "").Replace("\r\n", "\n").Split('\n'))
            {
                var m = Kv.Match(line); if (!m.Success) continue;
                var k = m.Groups[1].Value; var v = m.Groups[2].Value.Trim();
                if (k.EndsWith("User Profile", StringComparison.OrdinalIgnoreCase) && v.Length > 0 && !l.Contains(v)) l.Add(v);
            }
            return l;
        }
        public static WifiProfile ParseProfile(string name, string o)
        {
            if (string.IsNullOrWhiteSpace(o)) return null;
            var p = new WifiProfile { Name = name }; string key = null; bool sawAuth = false;
            foreach (var line in o.Replace("\r\n", "\n").Split('\n'))
            {
                var m = Kv.Match(line); if (!m.Success) continue;
                var k = m.Groups[1].Value.Trim(); var v = m.Groups[2].Value.Trim();
                if (k.Equals("Authentication", StringComparison.OrdinalIgnoreCase) && !sawAuth) { p.Auth = v; sawAuth = true; }
                else if (k.Equals("Cipher", StringComparison.OrdinalIgnoreCase) && p.Cipher == null) p.Cipher = v;
                else if (k.Equals("Connection mode", StringComparison.OrdinalIgnoreCase)) p.AutoConnect = v.IndexOf("auto", StringComparison.OrdinalIgnoreCase) >= 0;
                else if (k.Equals("Security key", StringComparison.OrdinalIgnoreCase)) key = v;
            }
            if (p.Auth == null) return null;
            p.Open = p.Auth.Equals("Open", StringComparison.OrdinalIgnoreCase) && (key == null || key.Equals("Absent", StringComparison.OrdinalIgnoreCase)) && !"WEP".Equals(p.Cipher, StringComparison.OrdinalIgnoreCase);
            p.Weak = !p.Open && (IsWeak(p.Auth, p.Cipher));
            return p;
        }
        public static bool IsWeak(string auth, string cipher)
        {
            if ("WEP".Equals(cipher, StringComparison.OrdinalIgnoreCase)) return true;
            if (auth == null) return false;
            var a = auth.ToUpperInvariant();
            return (a == "WPA-PERSONAL" || a == "WPA-ENTERPRISE" || a == "SHARED") || ("TKIP".Equals(cipher, StringComparison.OrdinalIgnoreCase) && !a.StartsWith("WPA3"));
        }
        // { SSID, Authentication, Cipher } of the first connected interface, or null
        public static string[] ParseInterfaces(string o)
        {
            if (string.IsNullOrWhiteSpace(o)) return null;
            string state = null, ssid = null, auth = null, cipher = null;
            Func<string[]> done = () => state != null && state.Equals("connected", StringComparison.OrdinalIgnoreCase) && ssid != null ? new[] { ssid, auth, cipher } : null;
            foreach (var line in o.Replace("\r\n", "\n").Split('\n'))
            {
                var m = Kv.Match(line); if (!m.Success) continue;
                var k = m.Groups[1].Value.Trim(); var v = m.Groups[2].Value.Trim();
                if (k.Equals("Name", StringComparison.OrdinalIgnoreCase)) { var r = done(); if (r != null) return r; state = ssid = auth = cipher = null; }
                else if (k.Equals("State", StringComparison.OrdinalIgnoreCase)) state = v;
                else if (k.Equals("SSID", StringComparison.OrdinalIgnoreCase)) ssid = v;
                else if (k.Equals("Authentication", StringComparison.OrdinalIgnoreCase)) auth = v;
                else if (k.Equals("Cipher", StringComparison.OrdinalIgnoreCase)) cipher = v;
            }
            return done();
        }
    }

    // ---------------- the rules
    public static class HardScore
    {
        public const int Cap = 10;
        public const string Group = "hardening";
        public static readonly string[] DefenderIds = { "pua", "cloud", "samples", "netprot", "asr", "exclusions" };
        static Check C(string id, string title, CheckState st, int pen, string line, string fixLabel = null, string fix = null)
        { return new Check { Id = id, Title = title, State = st, Penalty = pen, Line = line, FixLabel = fixLabel, FixAction = fix, Group = Group }; }
        static string N(int n, string one, string many) { return n + " " + (n == 1 ? one : many); }
        static string List(IEnumerable<string> l, int max = 4)
        {
            var a = l.ToList(); if (a.Count <= max) return string.Join(", ", a);
            return string.Join(", ", a.Take(max)) + " and " + (a.Count - max) + " more";
        }
        const string Threat = "windowsdefender://threatsettings", AppBrowser = "windowsdefender://appbrowser";

        public static List<Check> Evaluate(HardeningFacts h, SystemFacts sys)
        {
            var r = new List<Check>();
            if (h == null) return r;
            var otherAv = sys != null && sys.OtherAv.Count > 0 ? sys.OtherAv[0] : null;
            r.AddRange(Defender(h, otherAv));
            r.Add(Rdp(h)); r.Add(Tools(h));
            r.Add(Smb1(h)); r.Add(Ps2(h)); r.Add(AutoPlay(h));
            r.AddRange(Accounts(h, sys));
            r.AddRange(Wifi(h));
            return r;
        }

        // ---- Defender settings
        public static List<Check> Defender(HardeningFacts h, string otherAv)
        {
            var r = new List<Check>(); var p = h.Mp ?? new DefenderPrefs();
            if (otherAv != null)
            {
                r.Add(C("pua", "Defender settings", CheckState.Info, 0, otherAv + " is the antivirus here, so Microsoft Defender's own settings (PUA, cloud protection, exclusions) don't apply right now."));
                return r;
            }
            if (!p.Read)
            {
                r.Add(C("pua", "Defender settings", CheckState.Unknown, 0, "Couldn't read Microsoft Defender's settings. Windows Security shows them.", "Open settings", Threat));
                return r;
            }
            // PUA protection
            if (p.Pua == 1) r.Add(C("pua", "Potentially unwanted apps", CheckState.Good, 0, "Blocked - Defender stops adware, bundled toolbars and coin miners from installing."));
            else if (p.Pua == 2) r.Add(C("pua", "Potentially unwanted apps", CheckState.Warn, 1, "Audit mode only - Defender notes adware and bundled junk but lets it install. Turn on \"Block apps\" under Reputation-based protection.", "Open settings", AppBrowser));
            else if (p.Pua == 0) r.Add(C("pua", "Potentially unwanted apps", CheckState.Warn, 2, "Not blocked - adware, browser hijackers and coin miners that ride along with free downloads can install. Turn on \"Potentially unwanted app blocking\".", "Open settings", AppBrowser));
            else r.Add(C("pua", "Potentially unwanted apps", CheckState.Unknown, 0, "Couldn't read the PUA setting.", "Open settings", AppBrowser));
            // cloud-delivered protection
            if (p.Maps == null) r.Add(C("cloud", "Cloud-delivered protection", CheckState.Unknown, 0, "Couldn't read the cloud protection setting.", "Open settings", Threat));
            else if (p.Maps == 0) r.Add(C("cloud", "Cloud-delivered protection", CheckState.Warn, 3, "Off - Defender can't ask Microsoft's cloud about brand-new threats, so it reacts hours later instead of seconds.", "Open settings", Threat));
            else r.Add(C("cloud", "Cloud-delivered protection", CheckState.Good, 0, "On - brand-new threats are recognised within seconds."));
            // automatic sample submission
            if (p.Samples == null) r.Add(C("samples", "Automatic sample submission", CheckState.Unknown, 0, "Couldn't read the sample submission setting.", "Open settings", Threat));
            else if (p.Samples == 1 || p.Samples == 3) r.Add(C("samples", "Automatic sample submission", CheckState.Good, 0, p.Samples == 1 ? "On - suspicious programs (never your documents) are sent for a closer look." : "On - suspicious files are sent to Microsoft for a closer look."));
            else if (p.Samples == 2) r.Add(C("samples", "Automatic sample submission", CheckState.Warn, 1, "Off (never send) - cloud protection can't take a closer look at an unknown program, so it may be let through. Only programs are sent, not documents.", "Open settings", Threat));
            else r.Add(C("samples", "Automatic sample submission", CheckState.Info, 0, "Set to ask you every time - Defender waits for you before it sends a suspicious file.", "Open settings", Threat));
            // network protection
            if (p.NetProt == 1) r.Add(C("netprot", "Network protection", CheckState.Good, 0, "On - Defender blocks connections to known scam and malware sites from every app, not just the browser."));
            else if (p.NetProt == 2) r.Add(C("netprot", "Network protection", CheckState.Info, 0, "Audit mode - Defender notes connections to bad sites but doesn't block them.", "Show steps", "steps:netprot"));
            else if (p.NetProt == 0) r.Add(C("netprot", "Network protection", CheckState.Warn, 1, "Off - only the browser's SmartScreen blocks bad sites; other apps can still reach them. Windows Security has no switch for this - see the steps.", "Show steps", "steps:netprot"));
            else r.Add(C("netprot", "Network protection", CheckState.Unknown, 0, "Couldn't read the network protection setting."));
            // ASR rules
            if (p.AsrOn > 0) r.Add(C("asr", "Attack Surface Reduction rules", CheckState.Good, 0, N(p.AsrOn, "rule blocks", "rules block") + " common attack tricks (Office macros starting programs, scripts dropping files and similar)" + (p.AsrAudit + p.AsrWarn > 0 ? "; " + (p.AsrAudit + p.AsrWarn) + " more only watch." : ".")));
            else if (p.AsrRules > 0) r.Add(C("asr", "Attack Surface Reduction rules", CheckState.Info, 0, N(p.AsrRules, "rule is", "rules are") + " set up, but only in audit or warn mode - nothing is blocked yet.", "Show steps", "steps:asr"));
            else r.Add(C("asr", "Attack Surface Reduction rules", CheckState.Info, 0, "None on. These advanced rules block tricks like Office macros starting programs. Most home PCs don't use them - optional.", "Show steps", "steps:asr"));
            r.Add(Exclusions(h));
            return r;
        }
        public static Check Exclusions(HardeningFacts h)
        {
            const string title = "Defender exclusions"; var p = h.Mp;
            if (p.ExHidden) return C("exclusions", title, CheckState.Unknown, 0, "Windows only shows Defender's exclusions to administrators. Malware sometimes adds one to hide - click to check (Windows asks for admin first; it only reads them).", "Check (admin)", "admin:exclusions");
            var all = h.Exclusions ?? new List<ExclusionItem>();
            var when = p.ExFromAdminCheck && p.ExCheckedAt != null ? " (Checked as admin " + Score.Ago(p.ExCheckedAt, DateTime.Now) + ".)" : "";
            if (all.Count == 0) return C("exclusions", title, CheckState.Good, 0, "None - Defender checks everything." + when);
            var bad = all.Where(x => x.Flag != null).ToList();
            Func<ExclusionItem, string> show = x => (x.Kind == "extension" ? "." + x.Value.TrimStart('*').TrimStart('.') : x.Value) + (x.Flag != null ? " (" + x.Flag + ")" : "");
            if (bad.Count > 0)
                return C("exclusions", title, CheckState.Bad, 4, N(bad.Count, "exclusion is", "exclusions are") + " risky: " + List(bad.Select(show), 3) + ". Defender doesn't look there at all - malware often adds exclusions like these. Remove any you didn't add yourself.", "Open settings", Threat);
            return C("exclusions", title, CheckState.Info, 0, N(all.Count, "exclusion", "exclusions") + ": " + List(all.Select(show), 3) + ". None look risky - make sure you know why each one is there." + when, "Open settings", Threat);
        }

        // ---- remote access
        public static Check Rdp(HardeningFacts h)
        {
            const string title = "Remote Desktop";
            if (h.Rdp == null) return C("rdp", title, CheckState.Unknown, 0, "Couldn't read whether Remote Desktop is on.", "Open settings", "ms-settings:remotedesktop");
            if (h.Rdp == false) return C("rdp", title, CheckState.Good, 0, "Off - nobody can sign in to this PC over the network with Remote Desktop.");
            if (h.Nla == false) return C("rdp", title, CheckState.Bad, 4, "On, without Network Level Authentication - anyone who can reach the PC gets a sign-in screen, and old attacks (like BlueKeep) work before signing in. Turn on \"Require devices to use Network Level Authentication\", or turn Remote Desktop off if you don't use it.", "Open settings", "ms-settings:remotedesktop");
            return C("rdp", title, CheckState.Info, 0, "On, with Network Level Authentication - fine if you use it. If you don't, turning it off closes a door attackers like to knock on.", "Open settings", "ms-settings:remotedesktop");
        }
        public static string ToolText(RemoteTool t)
        {
            var bits = new List<string>();
            if (t.Running) bits.Add("running");
            if (t.Unattended) bits.Add("starts with Windows as a service - can be reached unattended");
            else if (t.AutoStart) bits.Add("starts with Windows");
            if (bits.Count == 0) bits.Add("installed");
            return t.Name + " (" + string.Join(", ", bits) + ")";
        }
        public const string AssistNote = " Hallow Assist isn't counted here - its unattended access is shown under Hallow apps.";
        public static Check Tools(HardeningFacts h)
        {
            const string title = "Remote-access apps";
            if (!h.ToolsRead) return C("tools", title, CheckState.Unknown, 0, "Couldn't look for remote-access apps.");
            if (h.Tools.Count == 0) return C("tools", title, CheckState.Good, 0, "None found (AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop, Splashtop and others)." + AssistNote);
            var always = h.Tools.Where(t => t.AutoStart).ToList();
            if (always.Count > 0)
                return C("tools", title, CheckState.Warn, 2, List(h.Tools.Select(ToolText)) + ". Fine if you set it up - scammers often install these to get in. If you don't use it, uninstall it." + AssistNote, "Open settings", "ms-settings:appsfeatures");
            return C("tools", title, CheckState.Info, 0, List(h.Tools.Select(ToolText)) + ". It only lets someone in while it runs - uninstall it if you don't use it." + AssistNote, "Open settings", "ms-settings:appsfeatures");
        }

        // ---- old or risky features
        public static Check Smb1(HardeningFacts h)
        {
            const string title = "SMBv1 file sharing";
            if (h.Smb1 == null) return C("smb1", title, CheckState.Unknown, 0, "Couldn't tell whether SMBv1 is installed.", "Open settings", "control:features");
            if (h.Smb1 == true) return C("smb1", title, CheckState.Bad, 3, "On - a 1980s file-sharing protocol that the WannaCry ransomware spread through. Nothing modern needs it: untick \"SMB 1.0/CIFS File Sharing Support\" in Windows features.", "Open settings", "control:features");
            return C("smb1", title, CheckState.Good, 0, "Off - the old protocol WannaCry spread through isn't installed.");
        }
        public static Check Ps2(HardeningFacts h)
        {
            const string title = "PowerShell 2.0 engine";
            if (h.Ps2 == null) return C("ps2", title, CheckState.Unknown, 0, "Couldn't tell whether the old PowerShell 2.0 engine is installed.", "Open settings", "control:features");
            if (h.Ps2 == true) return C("ps2", title, CheckState.Warn, 1, "Installed - attackers use this old engine to dodge the logging and malware scanning newer PowerShell has. Untick \"Windows PowerShell 2.0\" in Windows features.", "Open settings", "control:features");
            return C("ps2", title, CheckState.Good, 0, "Not installed - scripts can't fall back to the old engine to dodge malware scanning.");
        }
        public static Check AutoPlay(HardeningFacts h)
        {
            const string title = "AutoRun / AutoPlay for USB drives";
            if (h.AutoPlay == null) return C("autoplay", title, CheckState.Unknown, 0, "Couldn't read the AutoPlay setting.", "Open settings", "ms-settings:autoplay");
            if (h.AutoPlay == false) return C("autoplay", title, CheckState.Good, 0, "AutoPlay is off, and Windows never runs programs from a USB drive by itself (AutoRun).");
            return C("autoplay", title, CheckState.Info, 0, "Windows never runs programs from a USB drive by itself (AutoRun), but AutoPlay still offers to open what's on it. Setting removable drives to \"Take no action\" avoids a mis-click on a stranger's stick.", "Open settings", "ms-settings:autoplay");
        }

        // ---- accounts
        public static List<Check> Accounts(HardeningFacts h, SystemFacts sys)
        {
            var r = new List<Check>();
            if (!h.AccountsRead) { r.Add(C("accounts", "Accounts", CheckState.Unknown, 0, "Couldn't read this PC's local accounts.", "Open settings", "ms-settings:otherusers")); return r; }
            var on = h.Accounts.Where(a => !a.Disabled && !a.IsSystemOnly).ToList();
            var nopw = on.Where(a => !a.PasswordRequired && !a.IsGuest).ToList();
            if (nopw.Count > 0) r.Add(C("nopassword", "Accounts without a password", CheckState.Warn, 2, "Windows marks " + List(nopw.Select(a => a.Name)) + (nopw.Count == 1 ? " as not needing a password" : " as not needing passwords") + ". If one really has none, anyone at the PC - or on the network - can sign in as it. Give it a password or a PIN.", "Open settings", "ms-settings:otherusers"));
            else r.Add(C("nopassword", "Accounts without a password", CheckState.Good, 0, "Every account in use needs a password (" + N(on.Count(a => !a.IsGuest), "account", "accounts") + ")."));
            var guest = h.Accounts.FirstOrDefault(a => a.IsGuest);
            if (guest != null && !guest.Disabled) r.Add(C("guest", "Guest account", CheckState.Warn, 3, "On - anyone can sign in as \"" + guest.Name + "\" without a password. Windows keeps it off by default.", "Show steps", "steps:guest"));
            else r.Add(C("guest", "Guest account", CheckState.Good, 0, "Off."));
            var admins = on.Where(a => a.Admin).ToList();
            if (admins.Count > 1) r.Add(C("admins", "Administrators", CheckState.Warn, 1, N(admins.Count, "account is an administrator", "accounts are administrators") + ": " + List(admins.Select(a => a.Name)) + ". Each one can change anything on the PC - everyday accounts are safer as Standard users.", "Open settings", "ms-settings:otherusers"));
            else r.Add(C("admins", "Administrators", CheckState.Good, 0, admins.Count == 1 ? "One administrator (" + admins[0].Name + ")." : "No other administrator accounts in use."));
            bool uacNever = sys != null && (sys.Uac == false || sys.UacPrompts == false);
            if (h.CurrentIsAdmin == true && uacNever) r.Add(C("adminuac", "You as administrator", CheckState.Bad, 3, "You're signed in as an administrator and User Account Control is set to never notify - any program you run gets full control of the PC without asking. Move the slider up at least one notch.", "Open settings", "uac"));
            else if (h.CurrentIsAdmin == true) r.Add(C("adminuac", "You as administrator", CheckState.Good, 0, "You're an administrator, and Windows asks before a program gets admin rights."));
            else if (h.CurrentIsAdmin == false) r.Add(C("adminuac", "You as administrator", CheckState.Good, 0, "You use a Standard account - programs can't change the PC without an administrator's OK."));
            else r.Add(C("adminuac", "You as administrator", CheckState.Info, 0, "Couldn't tell whether your account is an administrator (it may be a domain account)."));
            return r;
        }

        // ---- Wi-Fi (names and security types only - never a password)
        public static List<Check> Wifi(HardeningFacts h)
        {
            var r = new List<Check>(); const string set = "ms-settings:network-wifisettings";
            if (!h.WifiRead) { r.Add(C("wifi", "Saved Wi-Fi networks", CheckState.Unknown, 0, "Couldn't read the saved Wi-Fi networks.")); return r; }
            if (h.NoWifi) { r.Add(C("wifi", "Wi-Fi", CheckState.Info, 0, "No Wi-Fi on this PC (or the Wi-Fi service is off) - nothing to check.")); return r; }
            var open = h.Wifi.Where(w => w.Open && w.AutoConnect).ToList();
            if (open.Count > 0) r.Add(C("wifi", "Saved Wi-Fi networks", CheckState.Warn, 2, N(open.Count, "open network connects", "open networks connect") + " by itself: " + List(open.Select(w => "\"" + w.Name + "\"")) + ". Anyone can set up a hotspot with the same name, and the PC joins it. Turn off \"Connect automatically\" or forget it.", "Open settings", set));
            else if (h.Wifi.Count == 0) r.Add(C("wifi", "Saved Wi-Fi networks", CheckState.Good, 0, "No saved Wi-Fi networks."));
            else r.Add(C("wifi", "Saved Wi-Fi networks", CheckState.Good, 0, N(h.Wifi.Count, "saved network", "saved networks") + (h.Wifi.Any(w => w.Open) ? " - the open ones only connect when you choose to." : ", all with a password.")));
            if (h.WifiConnected == null) r.Add(C("wifinow", "Wi-Fi right now", CheckState.Info, 0, "Not connected to Wi-Fi right now."));
            else
            {
                var sec = (h.WifiConnectedAuth ?? "unknown security") + (string.IsNullOrEmpty(h.WifiConnectedCipher) || h.WifiConnectedCipher.Equals("None", StringComparison.OrdinalIgnoreCase) ? "" : ", " + h.WifiConnectedCipher);
                bool isOpen = "Open".Equals(h.WifiConnectedAuth, StringComparison.OrdinalIgnoreCase) && !"WEP".Equals(h.WifiConnectedCipher, StringComparison.OrdinalIgnoreCase);
                if (isOpen) r.Add(C("wifinow", "Wi-Fi right now", CheckState.Warn, 2, "Connected to \"" + h.WifiConnected + "\" - an open network with no password (" + sec + "). Others nearby can see unencrypted traffic; avoid signing in to anything important here.", "Open settings", set));
                else if (PassesWeak(h.WifiConnectedAuth, h.WifiConnectedCipher)) r.Add(C("wifinow", "Wi-Fi right now", CheckState.Warn, 1, "Connected to \"" + h.WifiConnected + "\" with old, weak security (" + sec + "). If it's your router, switch it to WPA2 or WPA3.", "Open settings", set));
                else r.Add(C("wifinow", "Wi-Fi right now", CheckState.Good, 0, "Connected to \"" + h.WifiConnected + "\" (" + sec + ")."));
            }
            return r;
        }
        static bool PassesWeak(string auth, string cipher) { return HardeningProbe.IsWeak(auth, cipher); }

        // ---- the numbers
        public static int Penalty(List<Check> hard) { return hard == null ? 0 : Math.Min(Cap, hard.Sum(c => c.Penalty)); }
        public static int? GroupScore(List<Check> hard) { if (hard == null) return null; return Math.Max(0, 100 - hard.Sum(c => c.Penalty)); }

        // "Show steps" buttons (Guard never changes these itself)
        public static string[] Steps(string id)
        {
            switch (id)
            {
                case "netprot": return new[] { "Network protection",
                    "Windows Security has no switch for network protection on home PCs. If you want it on:\n\n1. Right-click Start > Terminal (Admin) and click Yes.\n2. Type:  Set-MpPreference -EnableNetworkProtection Enabled\n3. Press Enter. Hallow Guard shows the new state the next time it checks.\n\nTo undo it later: the same command with Disabled. Hallow Guard never changes this for you." };
                case "asr": return new[] { "Attack Surface Reduction rules",
                    "ASR rules block tricks malware uses - Office apps starting programs, scripts running downloaded files, stealing passwords from Windows' memory, and more.\n\nThey're an advanced, optional feature: on home PCs they're set with PowerShell as admin (Add-MpPreference -AttackSurfaceReductionRules_Ids <rule ID> -AttackSurfaceReductionRules_Actions Enabled). Microsoft's \"Attack surface reduction rules reference\" lists every rule and its ID.\n\nStart with audit mode (AuditMode instead of Enabled) for a week: some rules can block games' mod tools or older apps. Hallow Guard never changes this for you." };
                case "guest": return new[] { "Guest account",
                    "To turn the Guest account off:\n\n1. Right-click Start > Terminal (Admin) and click Yes.\n2. Type:  net user guest /active:no\n3. Press Enter.\n\n(On Windows Pro you can also use Computer Management > Local Users and Groups > Users > Guest > Account is disabled.) Hallow Guard never changes this for you." };
            }
            return null;
        }
    }

    // ---------------- the real PC (read-only)
    public class WmiMpPrefs : IMpPrefSource
    {
        public Dictionary<string, object> Read()
        {
            using (var s = new ManagementObjectSearcher(new ManagementScope(@"root\Microsoft\Windows\Defender"), new ObjectQuery("SELECT * FROM MSFT_MpPreference"), new EnumerationOptions { Timeout = TimeSpan.FromSeconds(20) }))
                foreach (ManagementObject o in s.Get())
                {
                    var d = new Dictionary<string, object>();
                    foreach (var p in o.Properties) d[p.Name] = p.Value;
                    return d;
                }
            return null;
        }
    }
    public class RealReg : IReg
    {
        static RegistryKey Open(string key)
        {
            var hive = key.StartsWith(@"HKCU\", StringComparison.OrdinalIgnoreCase) ? RegistryHive.CurrentUser : RegistryHive.LocalMachine;
            return RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(key.Substring(5));
        }
        public object Get(string key, string name) { using (var k = Open(key)) return k == null ? null : k.GetValue(name); }
        public string[] SubKeys(string key) { using (var k = Open(key)) return k == null ? new string[0] : k.GetSubKeyNames(); }
        public string[] ValueNames(string key) { using (var k = Open(key)) return k == null ? new string[0] : k.GetValueNames(); }
    }
    public class RealNetsh : INetsh
    {
        public string Run(string args)
        {
            var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "netsh.exe");
            if (!File.Exists(exe)) return null;
            var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
            try { psi.StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage); } catch { }
            using (var p = Process.Start(psi))
            {
                try { p.PriorityClass = ProcessPriorityClass.BelowNormal; } catch { }
                var err = p.StandardError.ReadToEndAsync();
                var o = p.StandardOutput.ReadToEndAsync();
                if (!p.WaitForExit(15000)) { try { p.Kill(); } catch { } return null; }
                return o.Result + err.Result;
            }
        }
    }
    public class WmiAccounts : IAccountSource
    {
        static IEnumerable<ManagementObject> Q(string wql)
        {
            using (var s = new ManagementObjectSearcher(new ManagementScope(@"root\cimv2"), new ObjectQuery(wql), new EnumerationOptions { Timeout = TimeSpan.FromSeconds(20) }))
                foreach (ManagementObject o in s.Get()) yield return o;
        }
        public List<LocalAccount> Read()
        {
            var l = new List<LocalAccount>();
            foreach (var o in Q("SELECT Name, SID, Disabled, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=True"))
                l.Add(new LocalAccount { Name = o["Name"] as string, Sid = o["SID"] as string, Disabled = o["Disabled"] is bool && (bool)o["Disabled"], PasswordRequired = !(o["PasswordRequired"] is bool) || (bool)o["PasswordRequired"] });
            // members of the local Administrators group (S-1-5-32-544; its name depends on the language)
            try
            {
                foreach (var g in Q("SELECT Name, Domain FROM Win32_Group WHERE LocalAccount=True AND SID='S-1-5-32-544'"))
                {
                    var q = "ASSOCIATORS OF {Win32_Group.Domain='" + ((string)g["Domain"]).Replace("'", "\\'") + "',Name='" + ((string)g["Name"]).Replace("'", "\\'") + "'} WHERE AssocClass=Win32_GroupUser ResultRole=PartComponent";
                    foreach (var m in Q(q))
                    {
                        string sid = null; try { sid = m["SID"] as string; } catch { }
                        foreach (var a in l) if (sid != null && a.Sid == sid) a.Admin = true;
                    }
                }
            }
            catch { }
            return l;
        }
    }
    public class RealProcs : IProcSource
    {
        public List<string> Names()
        {
            var l = new List<string>();
            foreach (var p in Process.GetProcesses()) { try { l.Add(p.ProcessName); } catch { } finally { p.Dispose(); } }
            return l;
        }
    }
    public class WmiFeatures : IFeatureSource
    {
        public Dictionary<string, int> Read(string[] names)
        {
            var d = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var where = string.Join(" OR ", names.Select(n => "Name='" + n.Replace("'", "") + "'"));
            using (var s = new ManagementObjectSearcher(new ManagementScope(@"root\cimv2"), new ObjectQuery("SELECT Name, InstallState FROM Win32_OptionalFeature WHERE " + where), new EnumerationOptions { Timeout = TimeSpan.FromSeconds(30) }))
                foreach (ManagementObject o in s.Get()) d[(string)o["Name"]] = Convert.ToInt32(o["InstallState"]);
            return d;
        }
    }

    // ---------------- made-up facts for --snap pictures (never this PC)
    public static class FakeHardening
    {
        public static HardeningFacts Sample()
        {
            var h = new HardeningFacts { When = DateTime.Now.AddMinutes(-3) };
            h.Mp = new DefenderPrefs { Read = true, Pua = 1, Maps = 2, Samples = 1, NetProt = 0, AsrRules = 0 };
            h.Mp.ExPaths.Add(@"D:\SteamLibrary\steamapps\common"); h.Mp.ExPaths.Add(@"C:\Users\Alex\AppData\Local\Temp");
            h.Mp.ExProcs.Add(@"C:\Users\Alex\AppData\Roaming\SysHelper\syshelper.exe");
            h.Exclusions = new List<ExclusionItem> {
                new ExclusionItem { Kind = "path", Value = @"D:\SteamLibrary\steamapps\common" },
                new ExclusionItem { Kind = "path", Value = @"C:\Users\Alex\AppData\Local\Temp", Flag = "the whole Temp folder" },
                new ExclusionItem { Kind = "process", Value = @"C:\Users\Alex\AppData\Roaming\SysHelper\syshelper.exe", Flag = "an unsigned file" } };
            h.Rdp = false; h.Nla = true;
            h.ToolsRead = true;
            h.Tools.Add(new RemoteTool { Name = "AnyDesk", Installed = true, Service = true, AutoStart = true, Running = true });
            h.Tools.Add(new RemoteTool { Name = "TeamViewer", Installed = true });
            h.Smb1 = false; h.Smb1How = "Windows features"; h.Ps2 = true; h.AutoPlay = true;
            h.AccountsRead = true; h.CurrentUser = "Alex"; h.CurrentIsAdmin = true;
            h.Accounts.Add(new LocalAccount { Name = "Administrator", Sid = "S-1-5-21-1-2-3-500", Disabled = true, Admin = true });
            h.Accounts.Add(new LocalAccount { Name = "Alex", Sid = "S-1-5-21-1-2-3-1001", Admin = true });
            h.Accounts.Add(new LocalAccount { Name = "Kids", Sid = "S-1-5-21-1-2-3-1002", PasswordRequired = false });
            h.Accounts.Add(new LocalAccount { Name = "Guest", Sid = "S-1-5-21-1-2-3-501", Disabled = true, PasswordRequired = false });
            h.WifiRead = true;
            h.Wifi.Add(new WifiProfile { Name = "HomeNet-5G", Auth = "WPA2-Personal", Cipher = "CCMP", AutoConnect = true });
            h.Wifi.Add(new WifiProfile { Name = "Cafe Free WiFi", Auth = "Open", Cipher = "None", AutoConnect = true, Open = true });
            h.Wifi.Add(new WifiProfile { Name = "Airport_Guest", Auth = "Open", Cipher = "None", AutoConnect = false, Open = true });
            h.Wifi.Add(new WifiProfile { Name = "Office", Auth = "WPA3-Personal", Cipher = "GCMP-256", AutoConnect = false });
            h.WifiConnected = "HomeNet-5G"; h.WifiConnectedAuth = "WPA2-Personal"; h.WifiConnectedCipher = "CCMP";
            return h;
        }
        // the same PC before anyone ran "Check (admin)": Windows hides the exclusion lists
        public static HardeningFacts Hidden() { var h = Sample(); h.Mp.ExHidden = true; h.Mp.ExPaths.Clear(); h.Mp.ExProcs.Clear(); h.Exclusions.Clear(); return h; }
        public static HardeningFacts Secure()
        {
            var h = Sample(); h.Mp.NetProt = 1; h.Mp.AsrRules = 3; h.Mp.AsrOn = 3; h.Mp.ExPaths.Clear(); h.Mp.ExProcs.Clear(); h.Exclusions.Clear();
            h.Tools.Clear(); h.Ps2 = false; h.AutoPlay = false; h.Accounts.RemoveAll(a => a.Name == "Kids"); h.Wifi.RemoveAll(w => w.Name == "Cafe Free WiFi");
            return h;
        }
    }
}
