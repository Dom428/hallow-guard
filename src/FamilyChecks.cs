// Hallow Guard v1.1 - the rest of the Hallow family in the one safety score. Read-only, and every part is optional:
//  - Hallow Keys: only the aggregate password-health counts Keys 2.8+ puts in its status.json (how many weak, reused, leaked, on a
//    breached site, missing 2FA - never a name, address or password). Guard never opens or reads the vault.
//  - Hallow Vault: last backup, failed backup checks, an unreachable second copy, and whether it's running (its status.json + pipe).
//  - Hallow Shield (a browser extension Guard can't talk to): looked for in Chrome / Edge / Brave / Opera profiles by reading COPIES
//    of each profile's Secure Preferences / Preferences (and the unpacked folder's manifest.json) - browser files are never changed.
//  - Hallow Assist: unattended access on or off (its status.json - no codes or secrets are in it).
// How it counts: an app that isn't installed costs nothing (it's shown with a line on why it helps and a link). Installed apps can
// lose a few points each (Keys at most 12, Vault at most 8, Shield 2, Assist 0); the "Hallow apps" score is 100 minus those, and the
// family score is the Windows score minus the same points, capped at 25 - so Windows always matters most.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Web.Script.Serialization;

namespace HallowGuard
{
    // what Guard could see of one Hallow app
    public class AppFacts
    {
        public string App; public bool Installed, Running;
        public Dictionary<string, object> Status;    // its status.json (null = none / unreadable)
        // missing = not installed; running = its pipe answers; stopped = installed, not running (whatever its status.json says)
        public string State { get { return !Installed ? "missing" : Running ? "running" : "stopped"; } }
    }
    public class ShieldFound { public string Profile, Version; public bool Enabled = true; }
    public class BrowserFacts { public string Name; public bool Present; public int Profiles; public List<ShieldFound> Found = new List<ShieldFound>(); }
    public class FamilyFacts
    {
        public AppFacts Keys = new AppFacts { App = "Keys" }, Vault = new AppFacts { App = "Vault" }, Assist = new AppFacts { App = "Assist" };
        public List<BrowserFacts> Browsers = new List<BrowserFacts>();
        public DateTime Now = DateTime.Now;
    }

    // where to look: the real PC, or fake folders in the tests
    public class FamilyEnv
    {
        public string ProgramsDir;                 // %LOCALAPPDATA%\Programs (Hallow <App>\Hallow<App>.exe)
        public Func<string, string> DataDir;       // app -> its data folder (status.json)
        public Func<string, bool> Running;         // app -> its family pipe is there
        public List<string[]> Browsers = new List<string[]>();   // { name, user data folder, "single" when that folder is the only profile (Opera) }
        public string TempDir;                     // where copies of browser files are read (deleted straight after)

        public static FamilyEnv Real()
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData); var roam = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var e = new FamilyEnv { ProgramsDir = Path.Combine(local, "Programs"), DataDir = Family.DataDir, Running = Family.Running, TempDir = Path.Combine(Path.GetTempPath(), "HallowGuard-browser-copies") };
            e.Browsers.Add(new[] { "Chrome", Path.Combine(local, @"Google\Chrome\User Data"), "" });
            e.Browsers.Add(new[] { "Edge", Path.Combine(local, @"Microsoft\Edge\User Data"), "" });
            e.Browsers.Add(new[] { "Brave", Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data"), "" });
            e.Browsers.Add(new[] { "Opera", Path.Combine(roam, @"Opera Software\Opera Stable"), "single" });
            e.Browsers.Add(new[] { "Opera GX", Path.Combine(roam, @"Opera Software\Opera GX Stable"), "single" });
            return e;
        }
        // developer tests: everything inside the test folder (Programs\, Hallow<App>\, Browsers\<name>\), the test pipes
        public static FamilyEnv ForTest(string dir)
        {
            var e = new FamilyEnv { ProgramsDir = Path.Combine(dir, "Programs"), DataDir = Family.DataDir, Running = Family.Running, TempDir = Path.Combine(dir, "browser-copies") };
            foreach (var b in new[] { "Chrome", "Edge", "Brave" }) e.Browsers.Add(new[] { b, Path.Combine(dir, "Browsers", b), "" });
            e.Browsers.Add(new[] { "Opera", Path.Combine(dir, "Browsers", "Opera"), "single" });
            return e;
        }
    }

    public static class J
    {
        static readonly JavaScriptSerializer js = new JavaScriptSerializer { MaxJsonLength = 32 * 1024 * 1024 };
        public static Dictionary<string, object> Parse(string json) { try { return js.DeserializeObject(json) as Dictionary<string, object>; } catch { return null; } }
        public static object Get(Dictionary<string, object> d, string k) { object v; return d != null && d.TryGetValue(k, out v) ? v : null; }
        public static string Str(Dictionary<string, object> d, string k) { return Get(d, k) as string; }
        public static Dictionary<string, object> Dict(Dictionary<string, object> d, string k) { return Get(d, k) as Dictionary<string, object>; }
        public static bool? Bool(Dictionary<string, object> d, string k) { var v = Get(d, k); return v is bool ? (bool?)(bool)v : null; }
        public static int? Int(Dictionary<string, object> d, string k)
        {
            var v = Get(d, k);
            try { if (v is int || v is long || v is decimal || v is double) { var n = Convert.ToInt64(v, CultureInfo.InvariantCulture); return n < 0 || n > int.MaxValue ? (int?)null : (int)n; } } catch { }
            return null;
        }
        public static DateTime? Time(Dictionary<string, object> d, string k)
        {
            var s = Str(d, k); DateTime t;
            return s != null && DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out t) ? t : (DateTime?)null;
        }
        public static IEnumerable<Dictionary<string, object>> List(Dictionary<string, object> d, string k)
        {
            var v = Get(d, k) as System.Collections.IEnumerable;
            if (v == null || v is string) yield break;
            foreach (var o in v) { var x = o as Dictionary<string, object>; if (x != null) yield return x; }
        }
    }

    public static class FamilyProbe
    {
        public static FamilyFacts Read(FamilyEnv e)
        {
            var f = new FamilyFacts { Keys = App(e, "Keys"), Vault = App(e, "Vault"), Assist = App(e, "Assist") };
            foreach (var b in e.Browsers)
            {
                try { f.Browsers.Add(ShieldScan.Browser(b[0], b[1], b[2] == "single", e.TempDir)); }
                catch { f.Browsers.Add(new BrowserFacts { Name = b[0] }); }
            }
            return f;
        }
        public static AppFacts App(FamilyEnv e, string app)
        {
            var a = new AppFacts { App = app };
            try { a.Installed = File.Exists(Path.Combine(e.ProgramsDir, "Hallow " + app, "Hallow" + app + ".exe")); } catch { }
            if (!a.Installed) return a;
            try { a.Running = e.Running(app); } catch { }
            try { var f = Path.Combine(e.DataDir(app), "status.json"); if (File.Exists(f)) a.Status = J.Parse(ReadShared(f, 4 * 1024 * 1024)); } catch { a.Status = null; }
            return a;
        }
        // reads a file another program may be writing (shared read, size limit); null when it can't
        public static string ReadShared(string path, long max)
        {
            try
            {
                using (var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                {
                    if (s.Length > max) return null;
                    using (var r = new StreamReader(s)) return r.ReadToEnd();
                }
            }
            catch { return null; }
        }
    }

    // Hallow Shield in the browsers' profiles (Chromium layout). Only copies are read; locked or odd files are skipped.
    public static class ShieldScan
    {
        public const string ExtensionName = "Hallow Shield";
        public static BrowserFacts Browser(string name, string root, bool single, string temp)
        {
            var b = new BrowserFacts { Name = name };
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) return b;
            b.Present = true;
            var profiles = new List<string>();
            if (single) profiles.Add(root);
            else
            {
                string[] dirs; try { dirs = Directory.GetDirectories(root); } catch { dirs = new string[0]; }
                foreach (var d in dirs.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                {
                    var n = Path.GetFileName(d);
                    if (n == "Default" || n.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase)) profiles.Add(d);
                }
            }
            foreach (var p in profiles)
            {
                if (!File.Exists(Path.Combine(p, "Preferences")) && !File.Exists(Path.Combine(p, "Secure Preferences"))) continue;
                b.Profiles++;
                ShieldFound hit = null; try { hit = Profile(p, temp); } catch { }
                if (hit != null) { hit.Profile = single ? "" : Path.GetFileName(p); b.Found.Add(hit); }
            }
            return b;
        }

        // the extension in one profile: its entry in (Secure) Preferences - the manifest stored there, or the unpacked folder's
        // manifest.json - or a packed copy under Extensions\<id>\<version>\
        public static ShieldFound Profile(string dir, string temp)
        {
            ShieldFound best = null;
            foreach (var prefs in new[] { "Secure Preferences", "Preferences" })
            {
                var root = J.Parse(ReadCopy(Path.Combine(dir, prefs), temp, 32 * 1024 * 1024));
                var settings = J.Dict(J.Dict(root, "extensions"), "settings");
                if (settings == null) continue;
                foreach (var kv in settings)
                {
                    var s = kv.Value as Dictionary<string, object>; if (s == null) continue;
                    var man = J.Dict(s, "manifest");
                    if (man == null)
                    {
                        var path = J.Str(s, "path");
                        if (!string.IsNullOrEmpty(path))
                            try { man = J.Parse(ReadCopy(Path.Combine(Path.IsPathRooted(path) ? path : Path.Combine(dir, "Extensions", path), "manifest.json"), temp, 1024 * 1024)); } catch { }
                    }
                    if (man == null || J.Str(man, "name") != ExtensionName) continue;
                    var hit = new ShieldFound { Version = J.Str(man, "version"), Enabled = Enabled(s) };
                    if (best == null || (!best.Enabled && hit.Enabled)) best = hit;
                }
                if (best != null) return best;
            }
            try
            {
                var ext = Path.Combine(dir, "Extensions");
                if (Directory.Exists(ext))
                    foreach (var id in Directory.GetDirectories(ext))
                        foreach (var ver in Directory.GetDirectories(id))
                        {
                            var man = J.Parse(ReadCopy(Path.Combine(ver, "manifest.json"), temp, 1024 * 1024));
                            if (man != null && J.Str(man, "name") == ExtensionName) return new ShieldFound { Version = J.Str(man, "version") };
                        }
            }
            catch { }
            return null;
        }
        // Chromium: "disable_reasons" (a number or a list) set = switched off; older versions: "state": 0
        public static bool Enabled(Dictionary<string, object> s)
        {
            var dr = J.Get(s, "disable_reasons");
            if (dr is int && (int)dr != 0) return false;
            if (dr is object[] && ((object[])dr).Length > 0) return false;
            var st = J.Get(s, "state");
            if (st is int && (int)st == 0) return false;
            return true;
        }
        // copies the file to Guard's own temp folder, reads the copy and deletes it - the browser's file is only ever read
        public static string ReadCopy(string file, string temp, long max)
        {
            try
            {
                if (!File.Exists(file) || new FileInfo(file).Length > max) return null;
                Directory.CreateDirectory(temp);
                var copy = Path.Combine(temp, Guid.NewGuid().ToString("N") + ".tmp");
                try { File.Copy(file, copy, true); return File.ReadAllText(copy); }
                finally { try { File.Delete(copy); } catch { } }
            }
            catch { return null; }
        }
    }

    public static class FamilyScore
    {
        public const string KeysUrl = "https://github.com/Dom428/hallow-keys", VaultUrl = "https://github.com/Dom428/hallow-vault",
            ShieldUrl = "https://github.com/Dom428/hallow-shield", AssistUrl = "https://github.com/Dom428/hallow-assist";
        public const int AppsCap = 25, KeysMax = 12, VaultMax = 8;

        static Check C(string id, string title, CheckState st, int pen, string line, string fixLabel = null, string fix = null)
        { return new Check { Id = id, Title = title, State = st, Penalty = pen, Line = line, FixLabel = fixLabel, FixAction = fix, Group = "apps" }; }
        static Check Missing(string id, string title, string why, string app, string url)
        { var c = C(id, title, CheckState.Info, 0, "Not installed. " + why, "Get " + app, "url:" + url); c.NotInstalled = true; return c; }
        static string N(int n, string one, string many) { return n + " " + (n == 1 ? one : many); }

        public static List<Check> Evaluate(FamilyFacts f)
        {
            return new List<Check> { KeysCheck(f.Keys, f.Now), VaultCheck(f.Vault, f.Now), ShieldCheck(f.Browsers), AssistCheck(f.Assist) };
        }

        // ---- Hallow Keys: aggregate counts only
        public static Check KeysCheck(AppFacts a, DateTime now)
        {
            const string title = "Passwords (Hallow Keys)";
            if (a == null || !a.Installed) return Missing("keys", title, "A password manager that keeps every password in one encrypted file on this PC and tells you which ones are weak, reused or leaked.", "Hallow Keys", KeysUrl);
            if (a.Status == null) return C("keys", title, CheckState.Unknown, 0, "Hallow Keys hasn't written its status yet - open it once.", "Open Hallow Keys", "app:Keys");
            if (!a.Status.ContainsKey("health"))
                return C("keys", title, CheckState.Unknown, 0, "This Hallow Keys (" + (J.Str(a.Status, "version") ?? "older") + ") doesn't share password health yet. Version 2.8 does - counts only, never a password or a name.", "Update Hallow Keys", "url:" + KeysUrl + "/releases/latest");
            var h = J.Dict(a.Status, "health");
            DateTime? when = J.Time(h, "when"); int? logins = J.Int(h, "logins");
            if (h == null || when == null || logins == null)
                return C("keys", title, CheckState.Unknown, 0, "Unlock Hallow Keys once and Guard shows here how many passwords are weak, reused or leaked (counts only).", "Open Hallow Keys", "app:Keys");
            var age = now - when.Value;
            if (age.TotalDays > 90) return C("keys", title, CheckState.Unknown, 0, "Hallow Keys last counted your passwords " + Score.Ago(when, now) + " - unlock it to refresh.", "Open Hallow Keys", "app:Keys");
            if (logins == 0) return C("keys", title, CheckState.Good, 0, "No logins saved in Hallow Keys yet.");
            int weak = J.Int(h, "weak") ?? 0, reused = J.Int(h, "reused") ?? 0, leaked = J.Int(h, "leaked") ?? 0, breached = J.Int(h, "breached") ?? 0, twofa = J.Int(h, "missing2fa") ?? 0;
            int pen = 0; var parts = new List<string>();
            if (leaked + breached > 0) { pen += 8; if (leaked > 0) parts.Add(N(leaked, "leaked password", "leaked passwords")); if (breached > 0) parts.Add(N(breached, "login on a breached site", "logins on breached sites")); }
            if (reused > 0) { pen += 5; parts.Add(N(reused, "reused password", "reused passwords")); }
            if (weak > 0) { pen += 4; parts.Add(N(weak, "weak password", "weak passwords")); }
            if (twofa > 0) { pen += 2; parts.Add(N(twofa, "site that offers 2FA you haven't set up", "sites that offer 2FA you haven't set up")); }
            pen = Math.Min(KeysMax, pen);
            var stamp = age.TotalHours >= 1 ? " Counted " + Score.Ago(when, now) + (age.TotalDays > 30 ? " - unlock Hallow Keys to refresh." : ".") : "";
            if (pen == 0) return C("keys", title, CheckState.Good, 0, "All " + logins + " logins look healthy - nothing weak, reused or leaked." + stamp);
            return C("keys", title, leaked + breached > 0 ? CheckState.Bad : CheckState.Warn, pen,
                "Of your " + logins + " logins: " + string.Join(", ", parts) + ". Hallow Keys' Password Health shows which ones and how to fix them." + stamp, "Open Hallow Keys", "app:Keys");
        }

        // ---- Hallow Vault: backups happening and not failing
        public static Check VaultCheck(AppFacts a, DateTime now)
        {
            const string title = "Game save backups (Hallow Vault)";
            if (a == null || !a.Installed) return Missing("vault", title, "Backs up your game saves automatically, so a crash, a bad patch or a new PC can't wipe your progress.", "Hallow Vault", VaultUrl);
            if (a.Status == null) return C("vault", title, CheckState.Unknown, 0, "Hallow Vault hasn't written its status yet - open it once.", a.Running ? "Open Hallow Vault" : "Start Hallow Vault", a.Running ? "app:Vault" : "app:start:Vault");
            var games = J.List(a.Status, "games").Where(g => J.Bool(g, "off") != true).ToList();
            DateTime? newest = null; foreach (var g in games) { var t = J.Time(g, "lastBackup"); if (t != null && (newest == null || t > newest)) newest = t; }
            int damaged = Math.Max(J.Int(J.Dict(a.Status, "lastCheck"), "damaged") ?? 0, games.Count(g => J.Str(g, "check") == "damaged"));
            var copy = J.Dict(a.Status, "secondCopy");
            int pen = 0; var st = CheckState.Good; var bad = new List<string>();
            Action<int, CheckState, string> add = (p, s, t) => { pen += p; if (s > st && s != CheckState.Unknown && s != CheckState.Info) st = s; bad.Add(t); };
            if (damaged > 0) add(6, CheckState.Bad, N(damaged, "backup failed", "backups failed") + " Vault's check - open Vault to see which.");
            if (copy != null && J.Bool(copy, "reachable") == false) add(3, CheckState.Warn, "The second-copy folder can't be reached, so backups only exist once.");
            if (games.Count > 0 && newest == null) add(3, CheckState.Warn, "No backups yet.");
            else if (newest != null && (now - newest.Value).TotalDays > 14) add(3, CheckState.Warn, "The last backup was " + Score.Ago(newest, now) + ".");
            if (!a.Running) add(2, CheckState.Warn, "Hallow Vault isn't running - it only backs up while it runs.");
            pen = Math.Min(VaultMax, pen);
            var summary = games.Count == 0 ? "Vault hasn't found a game to back up yet." : "Last backup " + Score.Ago(newest, now) + " (" + N(games.Count, "game", "games") + ").";
            if (pen == 0) return C("vault", title, games.Count == 0 ? CheckState.Info : CheckState.Good, 0, summary + " Backups are working.");
            return C("vault", title, st, pen, string.Join(" ", bad) + (newest != null && bad.All(b => !b.StartsWith("The last backup")) ? " Last backup " + Score.Ago(newest, now) + "." : ""),
                a.Running ? "Open Hallow Vault" : "Start Hallow Vault", a.Running ? "app:Vault" : "app:start:Vault");
        }

        // ---- Hallow Shield in the browsers
        public static Check ShieldCheck(List<BrowserFacts> browsers)
        {
            const string title = "Ad & tracker blocking (Hallow Shield)";
            var present = (browsers ?? new List<BrowserFacts>()).Where(b => b.Present).ToList();
            var with = present.Where(b => b.Found.Count > 0).ToList();
            const string why = "Blocks ads, trackers and YouTube ads right in the browser - nothing you browse leaves your PC.";
            if (present.Count == 0) { var c = Missing("shield", title, why + " (No Chrome, Edge, Brave or Opera was found here.)", "Hallow Shield", ShieldUrl); return c; }
            if (with.Count == 0) { var c = Missing("shield", title, why, "Hallow Shield", ShieldUrl); c.Line = "Not installed in " + string.Join(", ", present.Select(b => b.Name)) + ". " + why; return c; }
            var on = with.Where(b => b.Found.Any(x => x.Enabled)).ToList(); var off = with.Where(b => !b.Found.Any(x => x.Enabled)).ToList();
            Func<BrowserFacts, string> desc = b =>
            {
                var v = b.Found.Select(x => x.Version).Where(x => !string.IsNullOrEmpty(x)).Distinct().ToList();
                var profs = b.Found.Select(x => x.Profile).Where(x => !string.IsNullOrEmpty(x)).ToList();
                return b.Name + (v.Count > 0 ? " " + string.Join("/", v) : "") + (b.Profiles > 1 && profs.Count > 0 ? " (" + string.Join(", ", profs) + ")" : "");
            };
            var line = "Installed in " + string.Join(", ", with.Select(desc)) + ".";
            var without = present.Where(b => b.Found.Count == 0).Select(b => b.Name).ToList();
            if (without.Count > 0) line += " Not in " + string.Join(", ", without) + ".";
            if (off.Count > 0) return C("shield", title, CheckState.Warn, 2, line + " It's switched off in " + string.Join(", ", off.Select(b => b.Name)) + " - turn it on from the browser's extensions page.", "How to", "url:" + ShieldUrl + "#readme");
            return C("shield", title, CheckState.Good, 0, line);
        }

        // ---- Hallow Assist: unattended access is fine, but worth a line
        public static Check AssistCheck(AppFacts a)
        {
            const string title = "Remote help (Hallow Assist)";
            if (a == null || !a.Installed) return Missing("assist", title, "Remote help for family and friends: someone sees your screen only after you click Get help.", "Hallow Assist", AssistUrl);
            if (a.Status == null) return C("assist", title, CheckState.Unknown, 0, "Hallow Assist hasn't written its status yet - open it once.", "Open Hallow Assist", "app:Assist");
            var now = J.Str(a.Status, "session") == "connected" && a.Running ? " Someone is connected right now." : "";
            if (J.Bool(a.Status, "unattended") == true)
                return C("assist", title, CheckState.Info, 0, "Unattended access is on — make sure its password is strong." + now, "Open Hallow Assist", "app:Assist");
            return C("assist", title, CheckState.Good, 0, "Unattended access is off - a session only starts when someone here clicks Get help." + now);
        }

        // ---- the numbers
        public static int AppsPenalty(List<Check> apps) { return apps == null ? 0 : apps.Sum(c => c.Penalty); }
        // null when no Hallow app is installed (then there's nothing to score)
        public static int? AppsScore(List<Check> apps) { if (apps == null || !apps.Any(c => !c.NotInstalled)) return null; return Math.Max(0, Math.Min(100, 100 - AppsPenalty(apps))); }
        public static int Combined(int windows, List<Check> apps) { if (windows < 0) return -1; return Math.Max(0, Math.Min(100, windows - Math.Min(AppsCap, AppsPenalty(apps)))); }
        // v1.2: minus the Network & browsers group too (capped at MoreScore.Cap)
        public static int Combined(int windows, List<Check> apps, List<Check> more) { var c = Combined(windows, apps); return c < 0 ? -1 : Math.Max(0, c - MoreScore.Penalty(more)); }
        // the one to-do list: what costs the most points first, only things with a button, never "not installed"
        public static List<Check> Todo(IEnumerable<Check> all, int max = 5)
        {
            return (all ?? new Check[0]).Where(c => c != null && c.FixAction != null && !c.NotInstalled && (c.Penalty > 0 || c.State == CheckState.Bad || c.State == CheckState.Warn))
                .OrderByDescending(c => c.Penalty).ThenBy(c => c.State == CheckState.Bad ? 0 : 1).ThenBy(c => c.Group == "windows" ? 0 : c.Group == "more" ? 1 : 2).Take(max).ToList();
        }
    }

    // made-up family for --snap pictures (never this PC's apps or browsers)
    public static class FakeFamily
    {
        public static FamilyFacts Sample()
        {
            var now = DateTime.Now;
            var f = new FamilyFacts { Now = now };
            f.Keys = new AppFacts { App = "Keys", Installed = true, Running = true, Status = J.Parse("{\"app\":\"Keys\",\"version\":\"2.8\",\"locked\":true,\"health\":{\"logins\":148,\"weak\":3,\"reused\":6,\"leaked\":0,\"breached\":0,\"missing2fa\":4,\"old\":11,\"score\":82,\"when\":\"" + Family.Time(now.AddHours(-5)) + "\",\"fresh\":false,\"ageMinutes\":300}}") };
            f.Vault = new AppFacts { App = "Vault", Installed = true, Running = true, Status = J.Parse("{\"app\":\"Vault\",\"version\":\"1.12\",\"games\":[{\"name\":\"Deep Rock Galactic\",\"lastBackup\":\"" + Family.Time(now.AddHours(-3)) + "\",\"off\":false},{\"name\":\"Stardew Valley\",\"lastBackup\":\"" + Family.Time(now.AddDays(-1)) + "\",\"off\":false}],\"lastCheck\":{\"damaged\":0},\"secondCopy\":null}") };
            f.Assist = new AppFacts { App = "Assist", Installed = false };
            f.Browsers.Add(new BrowserFacts { Name = "Chrome", Present = true, Profiles = 2, Found = { new ShieldFound { Profile = "Default", Version = "1.1" } } });
            f.Browsers.Add(new BrowserFacts { Name = "Edge", Present = true, Profiles = 1, Found = { new ShieldFound { Profile = "Default", Version = "1.1" } } });
            f.Browsers.Add(new BrowserFacts { Name = "Brave", Present = true, Profiles = 1 });
            f.Browsers.Add(new BrowserFacts { Name = "Opera" });
            return f;
        }
        public static FamilyFacts NoneInstalled()
        {
            var f = new FamilyFacts();
            f.Browsers.Add(new BrowserFacts { Name = "Edge", Present = true, Profiles = 1 });
            return f;
        }
    }
}
