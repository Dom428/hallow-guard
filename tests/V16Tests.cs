// Hallow Guard 1.6 tests: the hardening checks with fake data sources only - a fake MSFT_MpPreference, a fake registry (Remote
// Desktop, services, uninstall entries, Run keys, AutoPlay, SMBv1), fake netsh output (and proof that a Wi-Fi key is never asked
// for: no call ever contains key=clear, and SafeNetsh refuses one), fake accounts, a fake process list and fake Windows features.
// Nothing here reads or changes this PC's settings.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HallowGuard.Tests
{
    public class FakeReg : IReg
    {
        public readonly Dictionary<string, Dictionary<string, object>> Keys = new Dictionary<string, Dictionary<string, object>>(StringComparer.OrdinalIgnoreCase);
        public FakeReg Set(string key, string name, object v)
        {
            Dictionary<string, object> k; if (!Keys.TryGetValue(key, out k)) Keys[key] = k = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            if (name != null) k[name] = v; return this;
        }
        public object Get(string key, string name) { Dictionary<string, object> k; object v; return Keys.TryGetValue(key, out k) && k.TryGetValue(name, out v) ? v : null; }
        public string[] SubKeys(string key)
        {
            var pre = key.TrimEnd('\\') + "\\";
            return Keys.Keys.Where(k => k.StartsWith(pre, StringComparison.OrdinalIgnoreCase)).Select(k => k.Substring(pre.Length).Split('\\')[0]).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        public string[] ValueNames(string key) { Dictionary<string, object> k; return Keys.TryGetValue(key, out k) ? k.Keys.ToArray() : new string[0]; }
    }
    public class FakeNetshOut : INetsh
    {
        public readonly List<string> Calls = new List<string>();
        public string Profiles, Interfaces; public Dictionary<string, string> Profile = new Dictionary<string, string>();
        public string Run(string args)
        {
            Calls.Add(args);
            if (args == "wlan show profiles") return Profiles;
            if (args == "wlan show interfaces") return Interfaces;
            foreach (var kv in Profile) if (args == "wlan show profile name=\"" + kv.Key + "\"") return kv.Value;
            return "Profile is not found on the system.";
        }
    }
    public class FakeMp : IMpPrefSource { public Dictionary<string, object> D; public Dictionary<string, object> Read() { if (D == null) throw new Exception("no Defender"); return D; } }
    public class FakeAccounts : IAccountSource { public List<LocalAccount> L = new List<LocalAccount>(); public List<LocalAccount> Read() { return L; } }
    public class FakeProcs : IProcSource { public List<string> L = new List<string>(); public List<string> Names() { return L; } }
    public class FakeFeatures : IFeatureSource { public Dictionary<string, int> D; public Dictionary<string, int> Read(string[] n) { if (D == null) throw new UnauthorizedAccessException("needs admin"); return D; } }

    public static class V16Tests
    {
        static Action<bool, string> Ok;
        const string NA = "N/A: Must be an administrator to view exclusions";
        static readonly PathRoots Roots = new PathRoots { Temp = @"C:\Users\Alex\AppData\Local\Temp\", Roaming = @"C:\Users\Alex\AppData\Roaming", Local = @"C:\Users\Alex\AppData\Local", Downloads = @"C:\Users\Alex\Downloads", Windows = @"C:\Windows", HallowPrograms = @"C:\Users\Alex\AppData\Local\Programs" };

        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            Netsh(); WifiChecks(); DefenderPrefsChecks(); Exclusions(); RemoteDesktop(); RemoteTools(); Features(); AccountChecks(); Scoring(); Buttons(); Snapshots();
        }

        // a whole fake PC; tests change the parts they look at
        static HardeningEnv Env(FakeReg reg = null, FakeNetshOut ns = null, FakeMp mp = null, FakeAccounts acc = null, FakeProcs procs = null, FakeFeatures feats = null)
        {
            return new HardeningEnv
            {
                Reg = reg ?? new FakeReg(), Netsh = ns ?? WifiPc(), Mp = mp ?? new FakeMp { D = Prefs(1, 2, 1, 1) }, Accounts = acc ?? new FakeAccounts(), Procs = procs ?? new FakeProcs(),
                Features = feats ?? new FakeFeatures { D = new Dictionary<string, int> { { "SMB1Protocol", 2 } } }, CurrentUser = "Alex", Roots = Roots,
                FileExists = p => false, Signer = p => null, Expand = p => p.Replace("%TEMP%", @"C:\Users\Alex\AppData\Local\Temp").Replace("%APPDATA%", @"C:\Users\Alex\AppData\Roaming"), ExclusionsFile = null
            };
        }
        static Dictionary<string, object> Prefs(int pua, int maps, int samples, int np, string[] asr = null, byte[] acts = null, object paths = null, object exts = null, object procs = null)
        {
            return new Dictionary<string, object> { { "PUAProtection", (byte)pua }, { "MAPSReporting", (byte)maps }, { "SubmitSamplesConsent", (byte)samples }, { "EnableNetworkProtection", (byte)np },
                { "AttackSurfaceReductionRules_Ids", asr }, { "AttackSurfaceReductionRules_Actions", acts }, { "ExclusionPath", paths }, { "ExclusionExtension", exts }, { "ExclusionProcess", procs } };
        }
        static Check Find(List<Check> l, string id) { return l.FirstOrDefault(x => x.Id == id); }
        static List<Check> Eval(HardeningEnv e, SystemFacts sys = null) { return HardScore.Evaluate(HardeningProbe.Read(e), sys ?? new SystemFacts { Uac = true, UacPrompts = true }); }

        // ---------------- netsh: shown only, never a key
        const string ProfilesOut = "\r\nProfiles on interface Wi-Fi:\r\n\r\nGroup policy profiles (read only)\r\n---------------------------------\r\n    <None>\r\n\r\nUser profiles\r\n-------------\r\n    All User Profile     : HomeNet-5G\r\n    All User Profile     : Cafe Free WiFi\r\n    All User Profile     : Airport_Guest\r\n    All User Profile     : Old Router\r\n    All User Profile     : Say \"hi\"\r\n\r\nProfiles on interface Wi-Fi 6:\r\n\r\nUser profiles\r\n-------------\r\n    All User Profile     : HomeNet-5G\r\n";
        static string ProfileOut(string name, string auth, string cipher, string mode, string key)
        {
            return "\r\nProfile " + name + " on interface Wi-Fi:\r\n=======================================================================\r\n\r\nApplied: All User Profile\r\n\r\nProfile information\r\n-------------------\r\n    Version                : 1\r\n    Type                   : Wireless LAN\r\n    Name                   : " + name + "\r\n    Control options        :\r\n        Connection mode    : " + mode + "\r\n        Network broadcast  : Connect only if this network is broadcasting\r\n        AutoSwitch         : Do not switch to other networks\r\n\r\nConnectivity settings\r\n---------------------\r\n    Number of SSIDs        : 1\r\n    SSID name              : \"" + name + "\"\r\n    Network type           : Infrastructure\r\n    Radio type             : [ Any Radio Type ]\r\n\r\nSecurity settings\r\n-----------------\r\n    Authentication         : " + auth + "\r\n    Cipher                 : " + cipher + "\r\n    Authentication         : " + auth + "\r\n    Cipher                 : " + cipher + "\r\n    Security key           : " + key + "\r\n    Key Content            : hunter2-SHOULD-NEVER-APPEAR\r\n\r\nCost settings\r\n-------------\r\n    Cost                   : Unrestricted\r\n";
        }
        const string InterfacesOut = "\r\nThere are 2 interfaces on the system: \r\n\r\n    Name                   : Wi-Fi\r\n    Description            : Example Wireless Adapter\r\n    GUID                   : 00000000-0000-0000-0000-000000000001\r\n    Physical address       : 00:11:22:33:44:55\r\n    State                  : disconnected\r\n    Radio status           : Hardware On\r\n\r\n    Name                   : Wi-Fi 6\r\n    Description            : Example AX Adapter\r\n    GUID                   : 00000000-0000-0000-0000-000000000002\r\n    Physical address       : 00:11:22:33:44:66\r\n    State                  : connected\r\n    SSID                   : HomeNet-5G\r\n    BSSID                  : 00:11:22:33:44:77\r\n    Network type           : Infrastructure\r\n    Radio type             : 802.11ax\r\n    Authentication         : WPA2-Personal\r\n    Cipher                 : CCMP\r\n    Connection mode        : Auto Connect\r\n    Profile                : HomeNet-5G\r\n";
        static FakeNetshOut WifiPc()
        {
            var n = new FakeNetshOut { Profiles = ProfilesOut, Interfaces = InterfacesOut };
            n.Profile["HomeNet-5G"] = ProfileOut("HomeNet-5G", "WPA2-Personal", "CCMP", "Connect automatically", "Present");
            n.Profile["Cafe Free WiFi"] = ProfileOut("Cafe Free WiFi", "Open", "None", "Connect automatically", "Absent");
            n.Profile["Airport_Guest"] = ProfileOut("Airport_Guest", "Open", "None", "Connect manually", "Absent");
            n.Profile["Old Router"] = ProfileOut("Old Router", "Open", "WEP", "Connect automatically", "Present");
            return n;
        }
        static void Netsh()
        {
            Ok(SafeNetsh.Allowed("wlan show profiles") && SafeNetsh.Allowed("wlan show interfaces") && SafeNetsh.Allowed("wlan show profile name=\"HomeNet\""), "netsh: the three show commands are allowed");
            Ok(!SafeNetsh.Allowed("wlan show profile name=\"HomeNet\" key=clear") && !SafeNetsh.Allowed("wlan show profile name=\"HomeNet\" KEY=CLEAR") && !SafeNetsh.Allowed("wlan show profile name=\"a\" key = clear")
                && !SafeNetsh.Allowed("wlan export profile key=clear") && !SafeNetsh.Allowed("wlan show profile name=\"a\" \"b\"") && !SafeNetsh.Allowed("wlan set profileparameter name=\"a\" connectionmode=manual") && !SafeNetsh.Allowed(null),
                "netsh: key=clear (any case or spacing), export, set and extra arguments are refused");
            var inner = new FakeNetshOut { Profiles = ProfilesOut }; bool threw = false;
            try { new SafeNetsh(inner).Run("wlan show profile name=\"HomeNet-5G\" key=clear"); } catch (InvalidOperationException) { threw = true; }
            Ok(threw && inner.Calls.Count == 0, "netsh: a key=clear call throws before netsh is ever run");
            var ns = WifiPc(); var f = HardeningProbe.Read(Env(ns: ns));
            Ok(ns.Calls.Count > 0 && ns.Calls.All(c => c.IndexOf("key", StringComparison.OrdinalIgnoreCase) < 0), "netsh: the Wi-Fi check never asks for a key (" + ns.Calls.Count + " calls, none with key=)");
            Ok(ns.Calls.All(SafeNetsh.Allowed), "netsh: every call the check made is a show command");
            Ok(!ns.Calls.Any(c => c.Contains("Say")), "netsh: a network name with a quote in it is skipped, not passed to netsh");
            var cleaned = new SafeNetsh(ns).Run("wlan show profile name=\"HomeNet-5G\"");
            Ok(cleaned.IndexOf("Key Content", StringComparison.OrdinalIgnoreCase) < 0 && !cleaned.Contains("hunter2"), "netsh: a Key Content line is dropped even if netsh sent one");
            var all = string.Join("|", HardScore.Evaluate(f, null).Select(x => x.Line)) + string.Join("|", f.Wifi.Select(w => w.Name + w.Auth + w.Cipher)) + string.Join("|", f.Timings);
            Ok(!all.Contains("hunter2"), "netsh: no password text in any check line, profile or timing");
        }

        // ---------------- Wi-Fi
        static void WifiChecks()
        {
            var names = HardeningProbe.ProfileNames(ProfilesOut);
            Ok(names.Count == 5 && names[0] == "HomeNet-5G" && names.Contains("Cafe Free WiFi"), "wifi: profile names, duplicates across adapters once");
            var f = HardeningProbe.Read(Env());
            var cafe = f.Wifi.First(p => p.Name == "Cafe Free WiFi"); var airport = f.Wifi.First(p => p.Name == "Airport_Guest"); var home = f.Wifi.First(p => p.Name == "HomeNet-5G"); var old = f.Wifi.First(p => p.Name == "Old Router");
            Ok(cafe.Open && cafe.AutoConnect && airport.Open && !airport.AutoConnect && !home.Open && home.AutoConnect && home.Auth == "WPA2-Personal", "wifi: open / auto-connect read from the profile");
            Ok(!old.Open && old.Weak, "wifi: WEP is weak, not open");
            Ok(f.WifiConnected == "HomeNet-5G" && f.WifiConnectedAuth == "WPA2-Personal" && f.WifiConnectedCipher == "CCMP", "wifi: the connected network and its security (second adapter; BSSID isn't SSID)");
            var c = HardScore.Wifi(f);
            var w = Find(c, "wifi"); var now = Find(c, "wifinow");
            Ok(w.State == CheckState.Warn && w.Penalty == 2 && w.Line.Contains("Cafe Free WiFi") && !w.Line.Contains("Airport_Guest") && w.FixAction == "ms-settings:network-wifisettings", "wifi: an open network that connects by itself is a [WARN] (the manual one isn't)");
            Ok(now.State == CheckState.Good && now.Line.Contains("WPA2-Personal"), "wifi: connected over WPA2 is [OK], with its security type");
            f.WifiConnectedAuth = "Open"; f.WifiConnectedCipher = "None";
            Ok(Find(HardScore.Wifi(f), "wifinow").State == CheckState.Warn, "wifi: connected to an open network is a [WARN]");
            f.WifiConnectedAuth = "WPA-Personal"; f.WifiConnectedCipher = "TKIP";
            Ok(Find(HardScore.Wifi(f), "wifinow").Penalty == 1, "wifi: connected over old WPA/TKIP is a light [WARN]");
            f.WifiConnected = null;
            Ok(Find(HardScore.Wifi(f), "wifinow").State == CheckState.Info, "wifi: not connected is [INFO]");
            f.Wifi.RemoveAll(x => x.Open && x.AutoConnect);
            Ok(Find(HardScore.Wifi(f), "wifi").State == CheckState.Good, "wifi: no open auto-connect network is [OK]");
            var none = new FakeNetshOut { Profiles = "The Wireless AutoConfig Service (wlansvc) is not running.", Interfaces = "" };
            var nf = HardeningProbe.Read(Env(ns: none));
            Ok(nf.NoWifi && HardScore.Wifi(nf).Count == 1 && HardScore.Wifi(nf)[0].State == CheckState.Info && none.Calls.Count == 1, "wifi: no Wi-Fi service is one [INFO] line, and nothing more is asked");
        }

        // ---------------- Defender settings
        static void DefenderPrefsChecks()
        {
            var c = Eval(Env(mp: new FakeMp { D = Prefs(1, 2, 1, 1, new[] { "a", "b", "c" }, new byte[] { 1, 2, 6 }) }));
            Ok(Find(c, "pua").State == CheckState.Good && Find(c, "cloud").State == CheckState.Good && Find(c, "samples").State == CheckState.Good && Find(c, "netprot").State == CheckState.Good, "defender: PUA, cloud, samples and network protection on are [OK]");
            var asr = Find(c, "asr");
            Ok(asr.State == CheckState.Good && asr.Line.StartsWith("1 rule blocks") && asr.Line.Contains("2 more only watch"), "defender: ASR counts blocking vs audit/warn rules");
            c = Eval(Env(mp: new FakeMp { D = Prefs(0, 0, 2, 0) }));
            Ok(Find(c, "pua").State == CheckState.Warn && Find(c, "pua").Penalty == 2 && Find(c, "pua").FixAction == "windowsdefender://appbrowser", "defender: PUA off is a [WARN] that opens Reputation-based protection");
            Ok(Find(c, "cloud").State == CheckState.Warn && Find(c, "cloud").Penalty == 3, "defender: cloud protection off is a [WARN] (3)");
            Ok(Find(c, "samples").State == CheckState.Warn && Find(c, "samples").Penalty == 1, "defender: never send samples is a light [WARN]");
            Ok(Find(c, "netprot").State == CheckState.Warn && Find(c, "netprot").FixAction == "steps:netprot", "defender: network protection off shows steps (Windows Security has no switch)");
            Ok(Find(c, "asr").State == CheckState.Info && Find(c, "asr").Penalty == 0, "defender: no ASR rules is [INFO] (optional), no points");
            c = Eval(Env(mp: new FakeMp { D = Prefs(2, 1, 0, 2, new[] { "a" }, new byte[] { 2 }) }));
            Ok(Find(c, "pua").Penalty == 1 && Find(c, "samples").State == CheckState.Info && Find(c, "netprot").State == CheckState.Info && Find(c, "asr").State == CheckState.Info, "defender: audit modes and 'always ask' are light");
            c = Eval(Env(mp: new FakeMp { D = null }));
            Ok(Find(c, "pua").State == CheckState.Unknown && c.Count(x => HardScore.DefenderIds.Contains(x.Id)) == 1, "defender: unreadable settings are one [UNK] line");
            var sys = new SystemFacts { Uac = true, UacPrompts = true }; sys.OtherAv.Add("Example Antivirus");
            c = Eval(Env(mp: new FakeMp { D = Prefs(0, 0, 2, 0) }), sys);
            Ok(Find(c, "pua").State == CheckState.Info && Find(c, "pua").Line.Contains("Example Antivirus") && Find(c, "cloud") == null && Find(c, "exclusions") == null, "defender: with another antivirus, Defender's settings are one [INFO] line and cost nothing");
        }

        // ---------------- exclusions
        static void Exclusions()
        {
            var c = Find(Eval(Env(mp: new FakeMp { D = Prefs(1, 2, 1, 1, null, null, new[] { NA }, new[] { NA }, new[] { NA }) })), "exclusions");
            Ok(c.State == CheckState.Unknown && c.FixLabel == "Check (admin)" && c.FixAction == "admin:exclusions" && c.Penalty == 0, "exclusions: admin-only lists -> \"Check (admin)\" like BitLocker");
            c = Find(Eval(Env(mp: new FakeMp { D = Prefs(1, 2, 1, 1) })), "exclusions");
            Ok(c.State == CheckState.Good, "exclusions: none is [OK]");
            Func<string, string> flag = p => HardeningProbe.PathFlag(p, Roots, x => x.EndsWith("unsigned.exe") || x.EndsWith("signed.exe"), x => x.EndsWith("\\signed.exe") ? "Example Ltd" : null, x => x.Replace("%TEMP%", @"C:\Users\Alex\AppData\Local\Temp").Replace("%USERPROFILE%", @"C:\Users\Alex"), false);
            Ok(flag(@"C:\") == "a whole drive" && flag("D:") == "a whole drive" && flag(@"E:\*") == "a whole drive", "exclusions: a whole drive is flagged");
            Ok(flag("%TEMP%") == "the whole Temp folder" && flag(@"C:\Users\Alex\AppData\Local\Temp\") == "the whole Temp folder" && flag(@"C:\Windows\Temp") == "the whole Temp folder", "exclusions: %TEMP% / Temp is flagged");
            Ok(flag(@"C:\Users\Alex\AppData") == "all of AppData" && flag(@"C:\Users\Alex\AppData\Roaming") == "all of AppData" && flag(@"C:\Users\Alex\AppData\Local\") == "all of AppData", "exclusions: AppData is flagged");
            Ok(flag(@"C:\Users\Alex\Downloads") == "the whole Downloads folder" && flag("%USERPROFILE%") == "your whole user folder" && flag(@"C:\Users") == "every user's folder" && flag(@"C:\Windows") == "the whole Windows folder", "exclusions: Downloads, the user folder and Windows are flagged");
            Ok(flag(@"C:\Users\Alex\AppData\Local\Temp\x\tool.exe") == "inside Temp", "exclusions: something inside Temp is flagged");
            Ok(flag(@"C:\Tools\unsigned.exe") == "an unsigned file" && flag(@"C:\Tools\signed.exe") == null, "exclusions: an unsigned program file is flagged, a signed one isn't");
            Ok(flag(@"C:\Users\Alex\AppData\Roaming\gone\gone.exe") == "a missing file in AppData", "exclusions: a missing program in AppData is flagged");
            Ok(flag(@"D:\SteamLibrary\steamapps\common") == null && flag(@"C:\Program Files\Example") == null, "exclusions: an ordinary game or program folder isn't flagged");
            Ok(flag("*") == "every file" && HardeningProbe.PathFlag("*.exe", Roots, null, null, null, true) == "every program" && flag(@"C:\Games\*.exe") == "every program in a folder", "exclusions: wildcards are flagged");
            Ok(HardeningProbe.ExtFlag("exe") == "every .exe file" && HardeningProbe.ExtFlag(".EXE") == "every .exe file" && HardeningProbe.ExtFlag("*.ps1") == "every .ps1 file" && HardeningProbe.ExtFlag("log") == null && HardeningProbe.ExtFlag("*") == "every file type", "exclusions: risky file types (.exe, .ps1) are flagged, .log isn't");
            var env = Env(mp: new FakeMp { D = Prefs(1, 2, 1, 1, null, null, new[] { @"D:\SteamLibrary", "%TEMP%" }, new[] { "exe" }, new[] { @"C:\Users\Alex\AppData\Roaming\x\x.exe", "game.exe" }) });
            var f = HardeningProbe.Read(env);
            Ok(f.Exclusions.Count == 5 && f.Exclusions.Count(x => x.Flag != null) == 3 && f.Exclusions.First(x => x.Value == "game.exe").Flag == null, "exclusions: paths, extensions and processes are all listed (a bare process name can't be checked)");
            c = Find(HardScore.Evaluate(f, null), "exclusions");
            Ok(c.State == CheckState.Bad && c.Penalty == 4 && c.Line.StartsWith("3 exclusions are risky") && c.Line.Contains("Temp") && c.FixAction == "windowsdefender://threatsettings", "exclusions: risky ones are a [RISK] (4) that opens Defender's settings");
            f = HardeningProbe.Read(Env(mp: new FakeMp { D = Prefs(1, 2, 1, 1, null, null, new[] { @"D:\SteamLibrary" }) }));
            c = Find(HardScore.Evaluate(f, null), "exclusions");
            Ok(c.State == CheckState.Info && c.Penalty == 0 && c.Line.Contains(@"D:\SteamLibrary"), "exclusions: harmless ones are [INFO], listed, no points");
            // what "Check (admin)" wrote (a file in the test folder - the real check runs only when clicked, through UAC)
            var file = Path.Combine(GuardSettings.Dir, "exclusions-test.json");
            try
            {
                Directory.CreateDirectory(GuardSettings.Dir);
                File.WriteAllText(file, "{\"paths\":[\"C:\\\\\"],\"exts\":[],\"procs\":[\"C:\\\\Tools\\\\a.exe\"]}");
                env = Env(mp: new FakeMp { D = Prefs(1, 2, 1, 1, null, null, NA, NA, NA) }); env.ExclusionsFile = file;
                f = HardeningProbe.Read(env);
                Ok(!f.Mp.ExHidden && f.Mp.ExFromAdminCheck && f.Mp.ExPaths.Count == 1 && f.Exclusions.Any(x => x.Flag == "a whole drive"), "exclusions: the admin check's result is used (a whole drive flagged)");
                File.SetLastWriteTime(file, DateTime.Now.AddDays(-8));
                Ok(HardeningProbe.Read(env).Mp.ExHidden, "exclusions: an admin check older than 7 days isn't trusted");
            }
            finally { try { File.Delete(file); } catch { } }
        }

        // ---------------- Remote Desktop
        static void RemoteDesktop()
        {
            const string ts = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", tcp = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", pol = @"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
            Func<FakeReg, Check> rdp = r => Find(Eval(Env(reg: r)), "rdp");
            Ok(rdp(new FakeReg().Set(ts, "fDenyTSConnections", 1).Set(tcp, "UserAuthentication", 1)).State == CheckState.Good, "rdp: off is [OK]");
            var on = rdp(new FakeReg().Set(ts, "fDenyTSConnections", 0).Set(tcp, "UserAuthentication", 1));
            Ok(on.State == CheckState.Info && on.Penalty == 0 && on.FixAction == "ms-settings:remotedesktop", "rdp: on with NLA is [INFO], opens Remote Desktop settings");
            var nonla = rdp(new FakeReg().Set(ts, "fDenyTSConnections", 0).Set(tcp, "UserAuthentication", 0));
            Ok(nonla.State == CheckState.Bad && nonla.Penalty == 4 && nonla.Line.Contains("Network Level Authentication"), "rdp: on without NLA is a [RISK] (4)");
            Ok(rdp(new FakeReg().Set(ts, "fDenyTSConnections", 0).Set(tcp, "UserAuthentication", 0).Set(pol, "fDenyTSConnections", 1)).State == CheckState.Good, "rdp: a policy that denies it wins");
            Ok(rdp(new FakeReg()).State == CheckState.Unknown, "rdp: unreadable is [UNK]");
        }

        // ---------------- remote-access tools
        static void RemoteTools()
        {
            const string un = @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", svc = @"HKLM\SYSTEM\CurrentControlSet\Services", run = @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            var reg = new FakeReg().Set(un + @"\AnyDesk", "DisplayName", "AnyDesk").Set(svc + @"\AnyDesk", "Start", 2).Set(un + @"\{HA}", "DisplayName", "Hallow Assist").Set(svc + @"\Spooler", "Start", 2).Set(un + @"\{X}", "DisplayName", "Example Editor");
            var procs = new FakeProcs { L = { "explorer", "TeamViewer", "HallowAssist" } };
            var f = HardeningProbe.Read(Env(reg: reg, procs: procs));
            var any = f.Tools.FirstOrDefault(t => t.Name == "AnyDesk"); var tv = f.Tools.FirstOrDefault(t => t.Name == "TeamViewer");
            Ok(f.Tools.Count == 2 && any != null && any.Installed && any.Unattended && !any.Running && tv != null && tv.Running && !tv.AutoStart, "tools: AnyDesk (auto-start service = unattended) and TeamViewer (running) found; Hallow Assist and others ignored");
            var c = HardScore.Tools(f);
            Ok(c.State == CheckState.Warn && c.Penalty == 2 && c.Line.Contains("AnyDesk (starts with Windows as a service - can be reached unattended)") && c.Line.Contains("TeamViewer (running)") && c.Line.Contains("Hallow Assist isn't counted here"), "tools: one that starts with Windows is a [WARN], says unattended, and points to Hallow Assist's own check");
            f = HardeningProbe.Read(Env(procs: new FakeProcs { L = { "rustdesk" } }));
            c = HardScore.Tools(f);
            Ok(c.State == CheckState.Info && c.Penalty == 0 && c.Line.StartsWith("RustDesk (running)"), "tools: only running (not starting with Windows) is [INFO]");
            f = HardeningProbe.Read(Env(reg: new FakeReg().Set(run, "Parsec.App.0", "\"C:\\Program Files\\Parsec\\parsecd.exe\" app_silent=1")));
            Ok(f.Tools.Count == 1 && f.Tools[0].Name == "Parsec" && f.Tools[0].AutoStart && !f.Tools[0].Unattended, "tools: a Run-key entry means it starts with you (not unattended)");
            f = HardeningProbe.Read(Env(reg: new FakeReg().Set(svc + @"\ScreenConnect Client (abc123)", "Start", 2)));
            Ok(f.Tools.Count == 1 && f.Tools[0].Name.StartsWith("ScreenConnect") && f.Tools[0].Unattended, "tools: a ScreenConnect client service (name with an ID) is found");
            f = HardeningProbe.Read(Env(reg: new FakeReg().Set(svc + @"\TeamViewer", "Start", 3)));
            Ok(f.Tools[0].Service && !f.Tools[0].AutoStart && HardScore.Tools(f).State == CheckState.Info, "tools: a manual-start service isn't unattended");
            f = HardeningProbe.Read(Env());
            Ok(HardScore.Tools(f).State == CheckState.Good, "tools: none is [OK]");
        }

        // ---------------- SMBv1, PowerShell 2.0, AutoPlay
        static void Features()
        {
            Func<FakeFeatures, FakeReg, HardeningFacts> read = (ft, rg) => HardeningProbe.Read(Env(reg: rg, feats: ft));
            var f = read(new FakeFeatures { D = new Dictionary<string, int> { { "SMB1Protocol", 1 }, { "MicrosoftWindowsPowerShellV2Root", 1 } } }, null);
            Ok(f.Smb1 == true && f.Smb1How == "Windows features" && HardScore.Smb1(f).State == CheckState.Bad && HardScore.Smb1(f).Penalty == 3 && HardScore.Smb1(f).FixAction == "control:features", "smb1: enabled feature is a [RISK] (3) that opens Windows features");
            Ok(f.Ps2 == true && HardScore.Ps2(f).State == CheckState.Warn && HardScore.Ps2(f).Penalty == 1, "ps2: the 2.0 engine installed is a light [WARN]");
            f = read(new FakeFeatures { D = new Dictionary<string, int> { { "SMB1Protocol", 2 } } }, null);
            Ok(f.Smb1 == false && f.Ps2 == false && HardScore.Smb1(f).State == CheckState.Good && HardScore.Ps2(f).State == CheckState.Good, "smb1 / ps2: disabled, or not part of this Windows, is [OK]");
            // Windows features can't be read (needs admin) -> the registry
            const string mrx = @"HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10", srv = @"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
            f = read(new FakeFeatures { D = null }, new FakeReg().Set(mrx, "Start", 2));
            Ok(f.Smb1 == true && f.Smb1How == "registry", "smb1: falls back to the registry - the SMBv1 client driver set to start means on");
            f = read(new FakeFeatures { D = null }, new FakeReg().Set(mrx, "Start", 4));
            Ok(f.Smb1 == false, "smb1: the driver disabled means off");
            f = read(new FakeFeatures { D = null }, new FakeReg().Set(srv, "SMB1", 1));
            Ok(f.Smb1 == true, "smb1: the server's SMB1 switch on means on");
            f = read(new FakeFeatures { D = null }, new FakeReg());
            Ok(f.Smb1 == false && f.Ps2 == null && HardScore.Ps2(f).State == CheckState.Unknown, "smb1: no driver means off; ps2 can't be told from the registry -> [UNK]");
            const string ap = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers";
            f = read(null, new FakeReg().Set(ap, "DisableAutoplay", 1));
            Ok(f.AutoPlay == false && HardScore.AutoPlay(f).State == CheckState.Good, "autoplay: off is [OK]");
            f = read(null, new FakeReg().Set(ap, "DisableAutoplay", 0));
            Ok(f.AutoPlay == true && HardScore.AutoPlay(f).State == CheckState.Info && HardScore.AutoPlay(f).FixAction == "ms-settings:autoplay", "autoplay: on is [INFO] (AutoRun never runs from USB) with a button to AutoPlay settings");
            f = read(null, new FakeReg().Set(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 0xFF));
            Ok(f.AutoPlay == false, "autoplay: a policy that turns it off for every drive counts as off");
        }

        // ---------------- accounts
        static LocalAccount A(string name, int rid, bool admin = false, bool pw = true, bool disabled = false) { return new LocalAccount { Name = name, Sid = "S-1-5-21-9-9-9-" + rid, Admin = admin, PasswordRequired = pw, Disabled = disabled }; }
        static void AccountChecks()
        {
            var acc = new FakeAccounts { L = { A("Administrator", 500, true, true, true), A("Alex", 1001, true), A("DefaultAccount", 503, false, false, true), A("WDAGUtilityAccount", 504, false, true, true), A("Guest", 501, false, false, true) } };
            var c = Eval(Env(acc: acc));
            Ok(Find(c, "nopassword").State == CheckState.Good && Find(c, "guest").State == CheckState.Good && Find(c, "admins").State == CheckState.Good && Find(c, "adminuac").State == CheckState.Good, "accounts: one admin with a password, Guest off - all [OK] (disabled and system accounts ignored)");
            acc.L.Add(A("Kids", 1002, false, false)); acc.L.Add(A("Sam", 1003, true)); acc.L.First(a => a.Name == "Guest").Disabled = false;
            c = Eval(Env(acc: acc));
            var np = Find(c, "nopassword");
            Ok(np.State == CheckState.Warn && np.Penalty == 2 && np.Line.Contains("Kids") && !np.Line.Contains("Guest") && np.FixAction == "ms-settings:otherusers", "accounts: an account Windows marks as not needing a password is a [WARN]");
            Ok(Find(c, "guest").State == CheckState.Warn && Find(c, "guest").Penalty == 3 && Find(c, "guest").FixAction == "steps:guest", "accounts: Guest on is a [WARN] (3) with steps");
            Ok(Find(c, "admins").State == CheckState.Warn && Find(c, "admins").Penalty == 1 && Find(c, "admins").Line.Contains("Alex") && Find(c, "admins").Line.Contains("Sam") && !Find(c, "admins").Line.Contains("Administrator"), "accounts: more than one admin in use is a light [WARN] (the disabled built-in one isn't counted)");
            var sys = new SystemFacts { Uac = true, UacPrompts = false };
            var au = Find(Eval(Env(acc: acc), sys), "adminuac");
            Ok(au.State == CheckState.Bad && au.Penalty == 3 && au.FixAction == "uac", "accounts: you as admin with UAC on never notify is a [RISK] that opens UAC settings");
            Ok(Find(Eval(Env(acc: acc), new SystemFacts { Uac = false, UacPrompts = true }), "adminuac").State == CheckState.Bad, "accounts: admin with UAC off entirely is a [RISK] too");
            var env = Env(acc: acc); env.CurrentUser = "Kids";
            Ok(Find(HardScore.Evaluate(HardeningProbe.Read(env), sys), "adminuac").State == CheckState.Good, "accounts: a Standard user isn't flagged even with UAC on never notify");
            env.CurrentUser = "someone@domain";
            Ok(Find(HardScore.Evaluate(HardeningProbe.Read(env), sys), "adminuac").State == CheckState.Info, "accounts: an account not in the local list (domain) is [INFO]");
        }

        // ---------------- the score: light, capped, in the to-do list
        static void Scoring()
        {
            var f = FakeHardening.Sample(); var c = HardScore.Evaluate(f, FakeProbe.Sample());
            int sum = c.Sum(x => x.Penalty);
            Ok(c.All(x => x.Group == HardScore.Group), "score: every hardening check is in the Hardening group");
            Ok(sum > HardScore.Cap && HardScore.Penalty(c) == HardScore.Cap && HardScore.GroupScore(c) == 100 - sum, "score: the group shows its own score (" + (100 - sum) + ") but takes at most " + HardScore.Cap + " off the family score");
            var win = Score.Evaluate(FakeProbe.Sample(), null); int ws = Score.Total(win);
            Ok(FamilyScore.Combined(ws, null, null, c) == Math.Max(0, ws - HardScore.Cap) && FamilyScore.Combined(ws, null, null, null) == ws && FamilyScore.Combined(-1, null, null, c) == -1, "score: the family score is the old one minus the capped Hardening points");
            var todo = FamilyScore.Todo(win.Concat(c));
            Ok(todo.Any(x => x.Group == HardScore.Group) && todo.First(x => x.Group == HardScore.Group).Id == "exclusions", "score: the riskiest hardening item (risky exclusions) makes the to-do list");
            Ok(c.Where(x => x.State == CheckState.Info || x.State == CheckState.Good).All(x => x.Penalty == 0), "score: [OK] and [INFO] lines never cost points");
            Ok(c.Max(x => x.Penalty) <= 4, "score: each hardening check costs at most 4 points (lightly)");
            Ok(HardScore.Penalty(null) == 0 && HardScore.GroupScore(null) == null, "score: no hardening read yet costs nothing");
        }

        // ---------------- buttons only open pages, show steps or run the read-only admin check
        static void Buttons()
        {
            var all = new List<Check>();
            foreach (var h in new[] { FakeHardening.Sample(), FakeHardening.Hidden(), FakeHardening.Secure() }) all.AddRange(HardScore.Evaluate(h, new SystemFacts { Uac = true, UacPrompts = false }));
            var acts = all.Where(x => x.FixAction != null).Select(x => x.FixAction).Distinct().ToList();
            Ok(acts.All(a => a.StartsWith("windowsdefender://") || a.StartsWith("ms-settings:") || a.StartsWith("steps:") || a == "admin:exclusions" || a == "control:features" || a == "uac"), "buttons: only Windows Security / Settings pages, steps, Windows features, UAC settings or the read-only admin check (" + string.Join(", ", acts) + ")");
            Ok(acts.Where(a => a.StartsWith("steps:")).All(a => HardScore.Steps(a.Substring(6)) != null), "buttons: every \"Show steps\" has steps");
            Ok(all.All(x => x.FixAction == null || !string.IsNullOrEmpty(x.FixLabel)), "buttons: every action has a label");
            Ok(all.All(x => !string.IsNullOrEmpty(x.Line) && !string.IsNullOrEmpty(x.Title) && Hud.Code(x.State).StartsWith("[")), "every check has a title, a plain-English line and a status code");
            // nothing in the hardening code runs a command that changes a setting
            var src = File.ReadAllText(Path.Combine(Path.GetDirectoryName(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName), @"..\src\Hardening.cs"));
            var code = string.Join("\n", src.Split('\n').Where(l => !l.TrimStart().StartsWith("//") && !l.Contains("\"Windows Security has no switch") && !l.Contains("ASR rules block") && !l.Contains("To turn the Guest account off")));
            Ok(!code.Contains("SetValue(") && !code.Contains("CreateSubKey") && !code.Contains("DeleteValue") && !code.Contains("InvokeMethod") && !code.Contains("Set-MpPreference") && !code.Contains("Add-MpPreference") && !code.Contains("key=clear\")"), "hardening code: no registry writes, no WMI methods, no Defender changes, no key=clear");
        }

        // ---------------- the made-up PC for --snap
        static void Snapshots()
        {
            var c = HardScore.Evaluate(FakeHardening.Sample(), FakeProbe.Sample());
            Ok(Find(c, "exclusions").State == CheckState.Bad && Find(c, "tools").State == CheckState.Warn && Find(c, "wifi").State == CheckState.Warn && Find(c, "ps2").State == CheckState.Warn && Find(c, "nopassword").State == CheckState.Warn, "snap data: a mix of [RISK], [WARN], [INFO] and [OK]");
            Ok(Find(HardScore.Evaluate(FakeHardening.Hidden(), FakeProbe.Sample()), "exclusions").FixAction == "admin:exclusions", "snap data: the before-admin-check picture shows Check (admin)");
            var s = HardScore.Evaluate(FakeHardening.Secure(), FakeProbe.Sample());
            Ok(s.All(x => x.State != CheckState.Bad), "snap data: the secure PC has no [RISK]");
            var f = HardeningProbe.Read(Env());
            Ok(f.Timings.Count == 6 && f.Timings.All(t => t.EndsWith(" ms")), "timings: each of the six parts is timed");
        }

        // ---------------- --real-hardening: the real read-only checks once, for timing (prints ids, states and timings only)
        public static int RealTiming()
        {
            try { System.Diagnostics.Process.GetCurrentProcess().PriorityClass = System.Diagnostics.ProcessPriorityClass.BelowNormal; } catch { }
            var env = HardeningEnv.Real(); env.ExclusionsFile = null;
            var calls = new List<string>(); var real = env.Netsh; env.Netsh = new RecordingNetsh(real, calls);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var f = HardeningProbe.Read(env);
            Console.WriteLine("hardening read in " + sw.ElapsedMilliseconds + " ms: " + string.Join(", ", f.Timings));
            var sys = new WindowsProbe().Read();
            foreach (var c in HardScore.Evaluate(f, sys)) Console.WriteLine("  " + Hud.Code(c.State).PadRight(7) + c.Id + (c.Penalty > 0 ? " -" + c.Penalty : "") + (c.FixAction != null ? "  [" + c.FixAction + "]" : ""));
            Console.WriteLine("netsh calls: " + calls.Count + ", any with key=: " + calls.Any(c => c.IndexOf("key", StringComparison.OrdinalIgnoreCase) >= 0));
            return calls.Any(c => c.IndexOf("key", StringComparison.OrdinalIgnoreCase) >= 0) ? 1 : 0;
        }
        class RecordingNetsh : INetsh
        {
            readonly INetsh inner; readonly List<string> calls;
            public RecordingNetsh(INetsh i, List<string> c) { inner = i; calls = c; }
            public string Run(string a) { calls.Add(a); return inner.Run(a); }
        }
    }
}
