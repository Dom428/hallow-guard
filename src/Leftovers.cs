// Hallow Guard - the leftover hunt: what starts with Windows (Run keys, Startup folders), scheduled tasks and services that
// aren't Microsoft's, programs running unsigned from Temp/AppData/Downloads, browser extensions and hosts-file entries.
// Read-only, except "Disable" for a startup entry in your own Run key, which moves it to a backup key Hallow Guard owns
// (HKCU\Software\HallowGuard\DisabledStartup) so it can be put back. Nothing is ever deleted.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace HallowGuard
{
    public enum Verdict { KnownGood, Unknown, Suspicious }

    public class Leftover
    {
        public string Kind;        // Startup, Task, Service, Process, Extension, Hosts
        public string Name, Detail, File, Signer, Where;
        public bool Autostart, Exists = true;
        public Verdict V; public string Reason;
        public string RunValue;    // a value in your own Run key (can be disabled)
        public string AdminKey;    // a machine-wide Run key entry (needs admin: Windows' Startup apps page instead)
        public string VerdictText { get { return V == Verdict.KnownGood ? "Known good" : V == Verdict.Suspicious ? "Suspicious" : "Unknown"; } }
    }

    // the folders that matter for the verdicts (tests pass their own)
    public class PathRoots
    {
        public string Temp, Roaming, Local, Downloads, Windows, HallowPrograms;
        public static PathRoots Current()
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return new PathRoots
            {
                Temp = Path.GetTempPath(), Roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Local = local,
                Downloads = DownloadWatcher.DownloadsFolder(), Windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                HallowPrograms = Path.Combine(local, "Programs")
            };
        }
    }

    public static class Classifier
    {
        // signers treated as well-known (matched against the start of the certificate's name)
        public static readonly string[] Publishers = {
            "Microsoft", "Google", "Mozilla", "Brave Software", "Opera Norway", "Apple", "Valve", "Epic Games", "NVIDIA", "Advanced Micro Devices", "AMD", "Intel",
            "Realtek", "Logitech", "Razer", "Corsair", "SteelSeries", "Discord", "Spotify", "Zoom Video", "Adobe", "Dropbox", "Oracle", "Electronic Arts",
            "Ubisoft", "Riot Games", "Blizzard", "Battle.net", "Activision", "Overwolf", "Dell", "HP Inc", "Hewlett", "Lenovo", "ASUSTeK", "Micro-Star", "MSI", "Gigabyte",
            "Samsung", "Western Digital", "Seagate", "Elgato", "Corel", "Malwarebytes", "Bitdefender", "ESET", "Kaspersky", "Avast", "AVG", "Norton", "Gen Digital",
            "McAfee", "Sophos", "Trend Micro", "Proton", "Mullvad", "NordVPN", "1Password", "AgileBits", "Bitwarden", "Signal", "Telegram", "WhatsApp", "Meta Platforms",
            "Slack", "Notepad++", "Igor Pavlov", "Python Software", "GitHub", "Docker", "JetBrains", "OBS Project", "Wondershare", "TeamViewer", "AnyDesk", "Cloudflare",
            "Plex", "VideoLAN", "Rockstar Games", "Take-Two", "CD PROJEKT", "GOG", "Tencent", "Easy Anti-Cheat", "BattlEye", "Wargaming", "Bethesda", "Nexus Mods", "Medal",
            "Elgato Systems", "Streamlabs", "Rainmeter", "Voicemod", "Wacom", "Canon", "Epson", "Brother Industries", "Synaptics", "Dolby", "Waves Audio", "Nahimic", "A-Volute" };

        public static bool IsWellKnown(string signer)
        {
            if (string.IsNullOrEmpty(signer)) return false;
            return Publishers.Any(p => signer.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        }
        static bool Under(string path, string root)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(root)) return false;
            var r = root.TrimEnd('\\') + "\\";
            return path.StartsWith(r, StringComparison.OrdinalIgnoreCase);
        }
        // a place programs shouldn't normally run from: Temp, AppData (except where per-user apps are installed: AppData\Local\Programs) or Downloads
        public static string RiskyPlace(string path, PathRoots r)
        {
            if (string.IsNullOrEmpty(path)) return null;
            if (Under(path, r.Temp) || Under(path, Path.Combine(r.Windows ?? "", "Temp")) || path.IndexOf("\\Temp\\", StringComparison.OrdinalIgnoreCase) >= 0) return "Temp";
            if (Under(path, r.Downloads)) return "Downloads";
            if (Under(path, r.HallowPrograms)) return null;
            if (Under(path, r.Roaming) || Under(path, r.Local) || path.IndexOf("\\AppData\\", StringComparison.OrdinalIgnoreCase) >= 0) return "AppData";
            return null;
        }
        public static bool IsHallow(string path, PathRoots r)
        {
            if (string.IsNullOrEmpty(path) || !Under(path, r.HallowPrograms)) return false;
            var rel = path.Substring(r.HallowPrograms.TrimEnd('\\').Length + 1);
            return Regex.IsMatch(rel, @"^Hallow [A-Za-z]+\\Hallow[A-Za-z]+\.exe$", RegexOptions.IgnoreCase);
        }

        // the verdict for a program file: Known good (Microsoft / a well-known publisher / Windows itself / a Hallow app), Unknown, or
        // Suspicious (unsigned AND in Temp/AppData/Downloads AND starts by itself)
        public static Verdict Classify(string path, bool exists, string signer, bool autostart, PathRoots r, out string reason)
        {
            if (string.IsNullOrEmpty(path)) { reason = "Couldn't tell which program this runs."; return Verdict.Unknown; }
            if (IsHallow(path, r)) { reason = "A Hallow app."; return Verdict.KnownGood; }
            if (!exists) { reason = "The program it points to isn't there any more - a leftover from something uninstalled."; return Verdict.Unknown; }
            if (!string.IsNullOrEmpty(signer))
            {
                if (IsWellKnown(signer)) { reason = "Signed by " + signer + "."; return Verdict.KnownGood; }
                reason = "Signed by " + signer + " - check you recognise it."; return Verdict.Unknown;
            }
            var place = RiskyPlace(path, r);
            if (place == null && Under(path, r.Windows)) { reason = "Part of Windows (in the Windows folder)."; return Verdict.KnownGood; }
            if (place != null && autostart) { reason = "Not signed, runs from " + place + " and starts by itself - malware often looks like this."; return Verdict.Suspicious; }
            if (place != null) { reason = "Not signed and runs from " + place + "."; return Verdict.Unknown; }
            reason = "Not signed - check you recognise it."; return Verdict.Unknown;
        }

        // a command line ("C:\x\y.exe" --tray, rundll32 z.dll,Entry, %windir%\..., unquoted paths with spaces) -> the program file
        public static string ExePath(string cmd)
        {
            if (string.IsNullOrWhiteSpace(cmd)) return null;
            var s = Environment.ExpandEnvironmentVariables(cmd.Trim());
            string exe, rest;
            if (s.StartsWith("\"")) { int q = s.IndexOf('"', 1); exe = q > 0 ? s.Substring(1, q - 1) : s.Trim('"'); rest = q > 0 ? s.Substring(q + 1).Trim() : ""; }
            else
            {
                exe = null; rest = "";
                var parts = s.Split(' ');
                for (int i = 1; i <= parts.Length; i++)
                {
                    var cand = string.Join(" ", parts.Take(i));
                    if (File.Exists(cand) || File.Exists(cand + ".exe")) { exe = File.Exists(cand) ? cand : cand + ".exe"; rest = string.Join(" ", parts.Skip(i)); break; }
                }
                if (exe == null) { var m = Regex.Match(s, @"^(.+?\.(exe|com|bat|cmd|dll|vbs|js|ps1|scr))(\s|,|$)", RegexOptions.IgnoreCase); exe = m.Success ? m.Groups[1].Value : parts[0]; rest = m.Success ? s.Substring(m.Groups[1].Length).Trim() : string.Join(" ", parts.Skip(1)); }
            }
            if (exe.StartsWith(@"\??\")) exe = exe.Substring(4);
            if (exe.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), exe.Substring(12));
            if (!exe.Contains("\\"))
            {
                var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                var c = Path.Combine(sys, exe); if (!Path.HasExtension(c)) c += ".exe";
                if (File.Exists(c)) exe = c;
            }
            // the real thing behind a Windows launcher is its first argument
            var name = Path.GetFileName(exe).ToLowerInvariant();
            if ((name == "rundll32.exe" || name == "regsvr32.exe") && rest.Length > 0)
            {
                var a = rest.Split(',')[0].Trim().Trim('"'); if (a.StartsWith("/")) a = a.Split(' ').Last().Trim('"');
                if (a.Length > 0) return ExePath("\"" + a + "\"") ?? exe;
            }
            if ((name == "wscript.exe" || name == "cscript.exe") && rest.Length > 0)
            {
                var m = Regex.Match(rest, "\"([^\"]+)\"|(\\S+\\.(vbs|js|wsf))", RegexOptions.IgnoreCase);
                if (m.Success) return m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            }
            return exe;
        }
    }

    // Authenticode: is the file signed with a valid signature, and by whom? (no network: revocation isn't checked)
    public static class Signing
    {
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern int WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, ref WINTRUST_DATA data);
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct WINTRUST_FILE_INFO { public int cbStruct; public string pcwszFilePath; public IntPtr hFile; public IntPtr pgKnownSubject; }
        [StructLayout(LayoutKind.Sequential)] struct WINTRUST_DATA
        {
            public int cbStruct; public IntPtr pPolicyCallbackData, pSIPClientData; public int dwUIChoice, fdwRevocationChecks, dwUnionChoice;
            public IntPtr pFile; public int dwStateAction; public IntPtr hWVTStateData; public IntPtr pwszURLReference; public int dwProvFlags, dwUIContext; public IntPtr pSignatureSettings;
        }
        static readonly Guid GenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        static readonly Dictionary<string, string> cache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static bool Verify(string path)
        {
            var fi = new WINTRUST_FILE_INFO { cbStruct = Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
            var pFile = Marshal.AllocHGlobal(fi.cbStruct);
            try
            {
                Marshal.StructureToPtr(fi, pFile, false);
                var d = new WINTRUST_DATA { cbStruct = Marshal.SizeOf(typeof(WINTRUST_DATA)), dwUIChoice = 2 /*none*/, fdwRevocationChecks = 0, dwUnionChoice = 1 /*file*/, pFile = pFile, dwStateAction = 1 /*verify*/, dwProvFlags = 0x1000 /*cache-only URL retrieval*/ | 0x80 /*no revocation*/ };
                int r = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref d);
                d.dwStateAction = 2; WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref d);   // close
                return r == 0;
            }
            catch { return false; }
            finally { Marshal.FreeHGlobal(pFile); }
        }
        // the signer's name when the file has a valid embedded signature; null when unsigned, invalid or missing
        public static string Signer(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            lock (cache) { string c; if (cache.TryGetValue(path, out c)) return c; }
            string s = null;
            try
            {
                if (File.Exists(path) && Verify(path))
                {
                    var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
                    s = cert.GetNameInfo(X509NameType.SimpleName, false);
                    if (string.IsNullOrEmpty(s)) s = "an unnamed publisher";
                }
            }
            catch { s = null; }
            lock (cache) cache[path] = s;
            return s;
        }
    }

    public interface ILeftoverSource { List<Leftover> Hunt(Action<string> progress); }

    public class WindowsLeftovers : ILeftoverSource
    {
        public const string UserRun = @"Software\Microsoft\Windows\CurrentVersion\Run";
        readonly PathRoots roots = PathRoots.Current();
        readonly HashSet<string> autostartFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public List<Leftover> Hunt(Action<string> progress)
        {
            var list = new List<Leftover>();
            Action<string, Action> step = (what, a) => { if (progress != null) progress(what); try { a(); } catch { } };
            step("Startup entries...", () => RunKeys(list));
            step("Startup folders...", () => StartupFolders(list));
            step("Scheduled tasks...", () => Tasks(list));
            step("Services...", () => Services(list));
            step("Running programs...", () => Processes(list));
            step("Browser extensions...", () => list.AddRange(Extensions.All()));
            step("Hosts file...", () => list.AddRange(Hosts.Read(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts"))));
            return list;
        }
        Leftover Program(string kind, string name, string cmd, bool autostart, string where)
        {
            var exe = Classifier.ExePath(cmd); bool exists = exe != null && File.Exists(exe);
            var signer = exists ? Signing.Signer(exe) : null; string reason;
            var v = Classifier.Classify(exe, exists, signer, autostart, roots, out reason);
            if (autostart && exe != null) autostartFiles.Add(exe);
            return new Leftover { Kind = kind, Name = name, Detail = cmd, File = exe, Exists = exists, Signer = signer, Autostart = autostart, V = v, Reason = reason, Where = where };
        }
        void RunKeys(List<Leftover> list)
        {
            var keys = new[] {
                Tuple.Create(Registry.CurrentUser, UserRun, true), Tuple.Create(Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", false),
                Tuple.Create(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", false),
                Tuple.Create(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", false),
                Tuple.Create(RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", false) };
            foreach (var k in keys)
                using (var key = k.Item1.OpenSubKey(k.Item2))
                {
                    if (key == null) continue;
                    var hive = k.Item1.Name.StartsWith("HKEY_CURRENT_USER") ? "HKCU" : "HKLM";
                    foreach (var n in key.GetValueNames())
                    {
                        if (n.Length == 0) continue;
                        var cmd = key.GetValue(n) as string; if (cmd == null) continue;
                        var l = Program("Startup", n, cmd, true, hive + "\\" + k.Item2);
                        if (k.Item3) l.RunValue = n; else if (hive == "HKLM") l.AdminKey = k.Item2;
                        list.Add(l);
                    }
                }
        }
        void StartupFolders(List<Leftover> list)
        {
            foreach (var dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
            {
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) continue;
                foreach (var f in Directory.GetFiles(dir))
                {
                    if (Path.GetFileName(f).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    var target = f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? Shortcut(f) : f;
                    var l = Program("Startup", Path.GetFileNameWithoutExtension(f), target == null ? f : "\"" + target + "\"", true, dir);
                    l.Detail = f; list.Add(l);
                }
            }
        }
        static string Shortcut(string lnk)
        {
            try
            {
                var t = Type.GetTypeFromProgID("WScript.Shell"); var sh = Activator.CreateInstance(t);
                try { var sc = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, sh, new object[] { lnk }); return sc.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, sc, null) as string; }
                finally { Marshal.FinalReleaseComObject(sh); }
            }
            catch { return null; }
        }
        static object Get(object o, string p, params object[] a) { return o.GetType().InvokeMember(p, BindingFlags.GetProperty, null, o, a.Length == 0 ? null : a); }
        static object Call(object o, string m, params object[] a) { return o.GetType().InvokeMember(m, BindingFlags.InvokeMethod, null, o, a); }
        void Tasks(List<Leftover> list)
        {
            var t = Type.GetTypeFromProgID("Schedule.Service"); var svc = Activator.CreateInstance(t);
            try
            {
                Call(svc, "Connect");
                var todo = new Stack<object>(); todo.Push(Call(svc, "GetFolder", "\\"));
                while (todo.Count > 0)
                {
                    var folder = todo.Pop(); var fpath = Get(folder, "Path") as string ?? "\\";
                    if (fpath.StartsWith("\\Microsoft", StringComparison.OrdinalIgnoreCase)) continue;
                    try
                    {
                        var tasks = Call(folder, "GetTasks", 1); int n = Convert.ToInt32(Get(tasks, "Count"));
                        for (int i = 1; i <= n; i++)
                        {
                            try
                            {
                                var task = Get(tasks, "Item", i); var name = Get(task, "Name") as string; var path = Get(task, "Path") as string;
                                bool enabled = Convert.ToBoolean(Get(task, "Enabled"));
                                var def = Get(task, "Definition"); var acts = Get(def, "Actions"); int na = Convert.ToInt32(Get(acts, "Count"));
                                string cmd = null;
                                for (int j = 1; j <= na && cmd == null; j++) { var a = Get(acts, "Item", j); if (Convert.ToInt32(Get(a, "Type")) == 0) { var p = Get(a, "Path") as string; var args = Get(a, "Arguments") as string; cmd = "\"" + Environment.ExpandEnvironmentVariables((p ?? "").Trim('"')) + "\"" + (string.IsNullOrEmpty(args) ? "" : " " + args); } }
                                if (cmd == null) continue;   // COM handlers / e-mail actions: nothing to check
                                var l = Program("Task", name, cmd, enabled, path);
                                if (!enabled) l.Reason += " (The task is disabled.)";
                                list.Add(l);
                            }
                            catch { }
                        }
                    }
                    catch { }
                    try { var subs = Call(folder, "GetFolders", 0); int ns = Convert.ToInt32(Get(subs, "Count")); for (int i = 1; i <= ns; i++) todo.Push(Get(subs, "Item", i)); } catch { }
                }
            }
            finally { Marshal.FinalReleaseComObject(svc); }
        }
        void Services(List<Leftover> list)
        {
            using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(@"SYSTEM\CurrentControlSet\Services"))
                foreach (var n in root.GetSubKeyNames())
                    try
                    {
                        using (var k = root.OpenSubKey(n))
                        {
                            var type = Convert.ToInt32(k.GetValue("Type", 0)); if ((type & 0x30) == 0) continue;   // drivers aren't services
                            var start = Convert.ToInt32(k.GetValue("Start", 3)); if (start == 4) continue;      // disabled
                            var img = k.GetValue("ImagePath") as string; if (string.IsNullOrEmpty(img)) continue;
                            var exe = Classifier.ExePath(img);
                            if (exe != null && Path.GetFileName(exe).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)) continue;   // Windows' shared service host
                            var signer = exe != null && File.Exists(exe) ? Signing.Signer(exe) : null;
                            if (signer != null && signer.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase)) continue;
                            if (signer == null && exe != null && exe.StartsWith(roots.Windows + "\\", StringComparison.OrdinalIgnoreCase)) continue;   // catalog-signed Windows parts
                            var disp = k.GetValue("DisplayName") as string; if (string.IsNullOrEmpty(disp) || disp.StartsWith("@")) disp = n;
                            var l = Program("Service", disp, img, start == 2, n + (start == 2 ? " (starts automatically)" : " (starts when needed)"));
                            list.Add(l);
                        }
                    }
                    catch { }
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(int access, bool inherit, int pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        public static string ProcessPath(int pid)
        {
            var h = OpenProcess(0x1000, false, pid); if (h == IntPtr.Zero) return null;
            try { var sb = new StringBuilder(1024); int n = sb.Capacity; return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null; }
            finally { CloseHandle(h); }
        }
        void Processes(List<Leftover> list)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in Process.GetProcesses())
                using (p)
                {
                    try
                    {
                        var path = ProcessPath(p.Id); if (path == null || !seen.Add(path)) continue;
                        var place = Classifier.RiskyPlace(path, roots); if (place == null || Classifier.IsHallow(path, roots)) continue;
                        if (Signing.Signer(path) != null) continue;
                        var auto = autostartFiles.Contains(path); string reason;
                        var v = Classifier.Classify(path, true, null, auto, roots, out reason);
                        list.Add(new Leftover { Kind = "Process", Name = p.ProcessName + " (process " + p.Id + ")", Detail = path, File = path, Autostart = auto, V = v, Reason = reason, Where = place });
                    }
                    catch { }
                }
        }
    }

    // browser extensions: Chrome, Edge, Brave (manifest.json in each profile) and Firefox (extensions.json)
    public static class Extensions
    {
        static readonly JavaScriptSerializer js = new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024 };
        public static List<Leftover> All()
        {
            var r = new List<Leftover>(); var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            foreach (var b in new[] { Tuple.Create("Chrome", @"Google\Chrome\User Data"), Tuple.Create("Edge", @"Microsoft\Edge\User Data"), Tuple.Create("Brave", @"BraveSoftware\Brave-Browser\User Data") })
                try { r.AddRange(Chromium(b.Item1, Path.Combine(local, b.Item2))); } catch { }
            try { r.AddRange(Firefox(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Mozilla\Firefox\Profiles"))); } catch { }
            return r;
        }
        public static List<Leftover> Chromium(string browser, string userData)
        {
            var r = new List<Leftover>(); if (!Directory.Exists(userData)) return r;
            foreach (var prof in Directory.GetDirectories(userData))
            {
                var pn = Path.GetFileName(prof); if (pn != "Default" && !pn.StartsWith("Profile ")) continue;
                var ext = Path.Combine(prof, "Extensions"); if (!Directory.Exists(ext)) continue;
                foreach (var idDir in Directory.GetDirectories(ext))
                {
                    var ver = Directory.GetDirectories(idDir).OrderByDescending(d => d).FirstOrDefault(d => File.Exists(Path.Combine(d, "manifest.json")));
                    if (ver == null) continue;
                    try { var l = FromManifest(browser, pn, Path.GetFileName(idDir), ver); if (l != null) r.Add(l); } catch { }
                }
            }
            return r;
        }
        public static Leftover FromManifest(string browser, string profile, string id, string dir)
        {
            var m = js.Deserialize<Dictionary<string, object>>(File.ReadAllText(Path.Combine(dir, "manifest.json")));
            var name = Str(m, "name") ?? id;
            if (name.StartsWith("__MSG_")) name = Localized(dir, Str(m, "default_locale") ?? "en", name.Substring(6).TrimEnd('_')) ?? id;
            var update = Str(m, "update_url") ?? "";
            bool store = update.Contains("clients2.google.com/service/update2/crx") || update.Contains("edge.microsoft.com/extensionwebstorebase");
            bool allSites = Perms(m).Any(p => p == "<all_urls>" || p == "*://*/*" || p == "http://*/*" || p == "https://*/*");
            var l = new Leftover { Kind = "Extension", Name = name, Detail = browser + " (" + profile + ") - " + id, File = dir, Where = browser };
            if (store) { l.V = Verdict.KnownGood; l.Reason = "From the " + (update.Contains("edge.microsoft.com") ? "Edge Add-ons" : "Chrome Web") + " store" + (allSites ? " - it can read and change every site you visit." : "."); }
            else if (allSites) { l.V = Verdict.Suspicious; l.Reason = "Not from the browser's store, and it can read and change every site you visit."; }
            else { l.V = Verdict.Unknown; l.Reason = "Not from the browser's store - check you installed it."; }
            return l;
        }
        static IEnumerable<string> Perms(Dictionary<string, object> m)
        {
            foreach (var key in new[] { "permissions", "host_permissions" })
            {
                object v; if (!m.TryGetValue(key, out v) || !(v is System.Collections.IEnumerable) || v is string) continue;
                foreach (var p in (System.Collections.IEnumerable)v) if (p is string) yield return (string)p;
            }
            object cs; if (m.TryGetValue("content_scripts", out cs) && cs is System.Collections.IEnumerable)
                foreach (var c in (System.Collections.IEnumerable)cs) { var d = c as Dictionary<string, object>; object mt; if (d != null && d.TryGetValue("matches", out mt) && mt is System.Collections.IEnumerable) foreach (var p in (System.Collections.IEnumerable)mt) if (p is string) yield return (string)p; }
        }
        static string Localized(string dir, string locale, string key)
        {
            foreach (var loc in new[] { locale, "en", "en_US" })
            {
                var f = Path.Combine(dir, "_locales", loc, "messages.json"); if (!File.Exists(f)) continue;
                var d = js.Deserialize<Dictionary<string, object>>(File.ReadAllText(f));
                foreach (var kv in d) if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase)) { var e = kv.Value as Dictionary<string, object>; var s = e == null ? null : Str(e, "message"); if (s != null) return s; }
            }
            return null;
        }
        public static List<Leftover> Firefox(string profiles)
        {
            var r = new List<Leftover>(); if (!Directory.Exists(profiles)) return r;
            foreach (var prof in Directory.GetDirectories(profiles))
            {
                var f = Path.Combine(prof, "extensions.json"); if (!File.Exists(f)) continue;
                try
                {
                    var d = js.Deserialize<Dictionary<string, object>>(File.ReadAllText(f)); object addons;
                    if (!d.TryGetValue("addons", out addons) || !(addons is System.Collections.IEnumerable)) continue;
                    foreach (var o in (System.Collections.IEnumerable)addons)
                    {
                        var a = o as Dictionary<string, object>; if (a == null || Str(a, "type") != "extension" || Str(a, "location") != "app-profile") continue;
                        object dl; var name = a.TryGetValue("defaultLocale", out dl) && dl is Dictionary<string, object> ? Str((Dictionary<string, object>)dl, "name") : null;
                        int signed = 0; object sv; if (a.TryGetValue("signedState", out sv) && sv != null) try { signed = Convert.ToInt32(sv); } catch { }
                        var l = new Leftover { Kind = "Extension", Name = name ?? Str(a, "id"), Detail = "Firefox (" + Path.GetFileName(prof) + ") - " + Str(a, "id"), File = Path.Combine(prof, "extensions"), Where = "Firefox" };
                        if (signed >= 2) { l.V = Verdict.KnownGood; l.Reason = "Signed by Mozilla (from addons.mozilla.org or checked by Mozilla)."; } else { l.V = Verdict.Unknown; l.Reason = "Not signed by Mozilla - check you installed it."; }
                        r.Add(l);
                    }
                }
                catch { }
            }
            return r;
        }
        static string Str(Dictionary<string, object> d, string k) { object v; return d != null && d.TryGetValue(k, out v) ? v as string : null; }
    }

    // the hosts file: every line that isn't a comment or the usual localhost entries
    public static class Hosts
    {
        static readonly string[] Sensitive = { "microsoft.com", "windowsupdate.com", "windows.com", "update.microsoft", "msftconnecttest.com", "virustotal.com", "malwarebytes.com", "bitdefender", "kaspersky", "eset.com", "avast.com", "norton", "mcafee", "google.com", "paypal.com", "apple.com", "steampowered.com", "steamcommunity.com", "discord.com", "github.com" };
        public static List<Leftover> Read(string file) { try { return Parse(File.ReadAllLines(file), file); } catch { return new List<Leftover>(); } }
        public static List<Leftover> Parse(IEnumerable<string> lines, string file)
        {
            var r = new List<Leftover>();
            foreach (var raw in lines)
            {
                var line = raw; int hash = line.IndexOf('#'); if (hash >= 0) line = line.Substring(0, hash);
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries); if (parts.Length < 2) continue;
                var ip = parts[0];
                foreach (var host in parts.Skip(1))
                {
                    var h = host.ToLowerInvariant();
                    if (h == "localhost" || h == "localhost.localdomain" || h == "local") continue;
                    bool block = ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "::1" || ip == "::";
                    bool sens = Sensitive.Any(s => h == s || h.EndsWith("." + s) || h.Contains(s));
                    var l = new Leftover { Kind = "Hosts", Name = h, Detail = ip + "  " + h, File = file, Where = "hosts file" };
                    if (sens && !block) { l.V = Verdict.Suspicious; l.Reason = "Sends " + h + " to a different address (" + ip + ") - malware does this to fake well-known sites."; }
                    else if (sens) { l.V = Verdict.Suspicious; l.Reason = "Blocks " + h + " - malware does this to stop security updates or tools. (Some privacy tools do it on purpose.)"; }
                    else if (block) { l.V = Verdict.Unknown; l.Reason = "Blocks " + h + " (often an ad or tracker blocker)."; }
                    else { l.V = Verdict.Unknown; l.Reason = "Sends " + h + " to " + ip + " (often for local networks or development)."; }
                    r.Add(l);
                }
            }
            return r;
        }
    }

    // "Disable" for a startup entry in your own Run key: the value moves to Hallow Guard's backup key, "Restore" moves it back.
    // Tests use their own fake keys (ForTest) and never the real Run key.
    public class DisabledEntry { public string Id, Name, Data, From, When; }
    public class StartupStore
    {
        public readonly string RunPath, BackupPath;
        public StartupStore(string runPath, string backupPath) { RunPath = runPath; BackupPath = backupPath; }
        public static StartupStore Real() { return new StartupStore(WindowsLeftovers.UserRun, @"Software\HallowGuard\DisabledStartup"); }
        public static StartupStore ForTest(string root) { return new StartupStore(root + @"\Run", root + @"\DisabledStartup"); }

        // returns an error message, or null when done
        public string Disable(string valueName)
        {
            try
            {
                using (var run = Registry.CurrentUser.OpenSubKey(RunPath, true))
                {
                    if (run == null || run.GetValue(valueName) == null) return "That startup entry isn't there any more.";
                    var kind = run.GetValueKind(valueName);
                    var data = run.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                    if (data == null) return "That entry isn't a normal startup command.";
                    using (var bk = Registry.CurrentUser.CreateSubKey(BackupPath))
                    {
                        var id = Safe(valueName); for (int i = 2; bk.OpenSubKey(id) != null; i++) id = Safe(valueName) + " (" + i + ")";
                        using (var e = bk.CreateSubKey(id))
                        {
                            e.SetValue("Name", valueName); e.SetValue("Data", data, kind == RegistryValueKind.ExpandString ? RegistryValueKind.ExpandString : RegistryValueKind.String);
                            e.SetValue("From", "HKCU\\" + RunPath); e.SetValue("When", DateTime.Now.ToString("o"));
                        }
                    }
                    run.DeleteValue(valueName);   // only after the backup is written
                }
                return null;
            }
            catch (Exception e) { return "Couldn't disable it: " + e.Message; }
        }
        public string Restore(string id)
        {
            try
            {
                using (var bk = Registry.CurrentUser.OpenSubKey(BackupPath, true))
                using (var e = bk == null ? null : bk.OpenSubKey(id))
                {
                    if (e == null) return "That entry isn't in the backup.";
                    var name = e.GetValue("Name") as string; var data = e.GetValue("Data", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                    if (string.IsNullOrEmpty(name) || data == null) return "The backup of that entry is damaged.";
                    var kind = e.GetValueKind("Data");
                    using (var run = Registry.CurrentUser.CreateSubKey(RunPath))
                    {
                        if (run.GetValue(name) != null) return "There's already a startup entry called " + name + ".";
                        run.SetValue(name, data, kind == RegistryValueKind.ExpandString ? RegistryValueKind.ExpandString : RegistryValueKind.String);
                    }
                    e.Close(); bk.DeleteSubKeyTree(id);
                }
                return null;
            }
            catch (Exception e) { return "Couldn't restore it: " + e.Message; }
        }
        public List<DisabledEntry> List()
        {
            var r = new List<DisabledEntry>();
            try
            {
                using (var bk = Registry.CurrentUser.OpenSubKey(BackupPath))
                    if (bk != null) foreach (var id in bk.GetSubKeyNames()) using (var e = bk.OpenSubKey(id))
                        r.Add(new DisabledEntry { Id = id, Name = e.GetValue("Name") as string, Data = e.GetValue("Data", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string, From = e.GetValue("From") as string, When = e.GetValue("When") as string });
            }
            catch { }
            return r;
        }
        static string Safe(string s) { var t = new string((s ?? "").Select(c => c == '\\' || char.IsControl(c) ? '_' : c).ToArray()).Trim(); return t.Length == 0 ? "entry" : t.Length > 200 ? t.Substring(0, 200) : t; }
    }

    // made-up leftovers for --snap pictures and tests
    public class FakeLeftovers : ILeftoverSource
    {
        public List<Leftover> Hunt(Action<string> progress)
        {
            return new List<Leftover> {
                new Leftover { Kind = "Startup", Name = "Discord", Detail = "\"C:\\Users\\Alex\\AppData\\Local\\Discord\\Update.exe\" --processStart Discord.exe", File = @"C:\Users\Alex\AppData\Local\Discord\Update.exe", Signer = "Discord Inc.", Autostart = true, V = Verdict.KnownGood, Reason = "Signed by Discord Inc.", RunValue = "Discord", Where = "HKCU" },
                new Leftover { Kind = "Startup", Name = "Hallow Hub", Detail = "\"C:\\Users\\Alex\\AppData\\Local\\Programs\\Hallow Hub\\HallowHub.exe\" --tray", File = @"C:\Users\Alex\AppData\Local\Programs\Hallow Hub\HallowHub.exe", Autostart = true, V = Verdict.KnownGood, Reason = "A Hallow app.", RunValue = "HallowHub", Where = "HKCU" },
                new Leftover { Kind = "Startup", Name = "SysHelper", Detail = "\"C:\\Users\\Alex\\AppData\\Roaming\\syshelper\\svc.exe\" -silent", File = @"C:\Users\Alex\AppData\Roaming\syshelper\svc.exe", Autostart = true, V = Verdict.Suspicious, Reason = "Not signed, runs from AppData and starts by itself - malware often looks like this.", RunValue = "SysHelper", Where = "HKCU" },
                new Leftover { Kind = "Startup", Name = "OldPrinterTool", Detail = "C:\\Program Files\\PrintTool\\ptray.exe", File = @"C:\Program Files\PrintTool\ptray.exe", Exists = false, Autostart = true, V = Verdict.Unknown, Reason = "The program it points to isn't there any more - a leftover from something uninstalled.", AdminKey = WindowsLeftovers.UserRun, Where = "HKLM" },
                new Leftover { Kind = "Task", Name = "GoogleUpdaterTaskUser", Detail = "\"C:\\Users\\Alex\\AppData\\Local\\Google\\GoogleUpdater\\updater.exe\" --wake", File = @"C:\Users\Alex\AppData\Local\Google\GoogleUpdater\updater.exe", Signer = "Google LLC", Autostart = true, V = Verdict.KnownGood, Reason = "Signed by Google LLC.", Where = "\\GoogleUpdaterTaskUser" },
                new Leftover { Kind = "Task", Name = "Coupon Finder Update", Detail = "\"C:\\Users\\Alex\\AppData\\Local\\CouponFinder\\cfupd.exe\"", File = @"C:\Users\Alex\AppData\Local\CouponFinder\cfupd.exe", Autostart = true, V = Verdict.Suspicious, Reason = "Not signed, runs from AppData and starts by itself - malware often looks like this.", Where = "\\Coupon Finder Update" },
                new Leftover { Kind = "Service", Name = "RGB Fusion Service", Detail = "\"C:\\Program Files\\RGBFusion\\rgbsvc.exe\"", File = @"C:\Program Files\RGBFusion\rgbsvc.exe", Signer = "Some Lighting Co., Ltd.", Autostart = true, V = Verdict.Unknown, Reason = "Signed by Some Lighting Co., Ltd. - check you recognise it.", Where = "RGBFusion (starts automatically)" },
                new Leftover { Kind = "Process", Name = "svc (process 9124)", Detail = @"C:\Users\Alex\AppData\Roaming\syshelper\svc.exe", File = @"C:\Users\Alex\AppData\Roaming\syshelper\svc.exe", Autostart = true, V = Verdict.Suspicious, Reason = "Not signed, runs from AppData and starts by itself - malware often looks like this.", Where = "AppData" },
                new Leftover { Kind = "Extension", Name = "uBlock Origin", Detail = "Chrome (Default) - cjpalhdlnbpafiamejdnhcphjbkeiagm", V = Verdict.KnownGood, Reason = "From the Chrome Web store - it can read and change every site you visit.", Where = "Chrome" },
                new Leftover { Kind = "Extension", Name = "Video Downloader Plus", Detail = "Edge (Default) - kpgjfoeplhomhlfdpbhmoolbmpogajbe", V = Verdict.Suspicious, Reason = "Not from the browser's store, and it can read and change every site you visit.", Where = "Edge" },
                new Leftover { Kind = "Hosts", Name = "ads.example.net", Detail = "0.0.0.0  ads.example.net", V = Verdict.Unknown, Reason = "Blocks ads.example.net (often an ad or tracker blocker).", Where = "hosts file" } };
        }
    }
}
