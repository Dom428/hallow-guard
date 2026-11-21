// Hallow Guard 1.1 unit tests: the Hallow family in the safety score, with fake status files for every app state (missing, running,
// stopped, stale), Hallow Shield found in fake Chrome / Edge / Brave / Opera profile folders (locked and broken files too, and the
// browser files never changed), the score math and the one to-do list. Everything in a temp folder; no real app or browser is read.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace HallowGuard.Tests
{
    public static class FamilyTests
    {
        static Action<bool, string> Ok;
        static string Root;
        static readonly HashSet<string> running = new HashSet<string>();

        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            Root = Path.Combine(Path.GetTempPath(), "HallowGuardFamilyTest" + System.Diagnostics.Process.GetCurrentProcess().Id);
            try
            {
                if (Directory.Exists(Root)) Directory.Delete(Root, true); Directory.CreateDirectory(Root);
                Apps(); Shield(); Numbers();
            }
            finally { try { Directory.Delete(Root, true); } catch { } }
        }

        static FamilyEnv Env()
        {
            var e = new FamilyEnv { ProgramsDir = Path.Combine(Root, "Programs"), DataDir = a => Path.Combine(Root, "Data", "Hallow" + a), Running = a => running.Contains(a), TempDir = Path.Combine(Root, "copies") };
            foreach (var b in new[] { "Chrome", "Edge", "Brave" }) e.Browsers.Add(new[] { b, Path.Combine(Root, "Browsers", b, "User Data"), "" });
            e.Browsers.Add(new[] { "Opera", Path.Combine(Root, "Browsers", "Opera Stable"), "single" });
            return e;
        }
        static void Install(string app) { var d = Path.Combine(Root, "Programs", "Hallow " + app); Directory.CreateDirectory(d); File.WriteAllText(Path.Combine(d, "Hallow" + app + ".exe"), "stand-in"); }
        static void Status(string app, string json) { var d = Path.Combine(Root, "Data", "Hallow" + app); Directory.CreateDirectory(d); File.WriteAllText(Path.Combine(d, "status.json"), json); }
        static void NoStatus(string app) { var f = Path.Combine(Root, "Data", "Hallow" + app, "status.json"); if (File.Exists(f)) File.Delete(f); }
        static string T(DateTime t) { return Family.Time(t); }
        static Check Keys(DateTime now) { return FamilyScore.KeysCheck(FamilyProbe.App(Env(), "Keys"), now); }
        static Check Vault(DateTime now) { return FamilyScore.VaultCheck(FamilyProbe.App(Env(), "Vault"), now); }
        static Check Assist() { return FamilyScore.AssistCheck(FamilyProbe.App(Env(), "Assist")); }
        static string Health(int logins, int weak, int reused, int leaked, string breached, string twofa, DateTime when)
        {
            return "{\"app\":\"Keys\",\"version\":\"2.8\",\"running\":true,\"locked\":true,\"health\":{\"logins\":" + logins + ",\"weak\":" + weak + ",\"reused\":" + reused + ",\"leaked\":" + leaked + ",\"breached\":" + breached + ",\"missing2fa\":" + twofa + ",\"old\":2,\"score\":80,\"when\":\"" + T(when) + "\",\"fresh\":false,\"ageMinutes\":5}}";
        }

        // ---------------- the apps' states, from fake status files
        static void Apps()
        {
            var now = new DateTime(2026, 11, 20, 12, 0, 0);
            // Keys
            var k = Keys(now);
            Ok(k.NotInstalled && k.Penalty == 0 && k.State == CheckState.Info && k.FixAction == "url:" + FamilyScore.KeysUrl && k.Line.StartsWith("Not installed."), "Keys missing: not installed, no points, why + link");
            Status("Keys", Health(40, 1, 2, 0, "0", "0", now));
            k = Keys(now); Ok(k.NotInstalled, "Keys: a leftover status.json without the app = still not installed");
            Install("Keys"); NoStatus("Keys");
            k = Keys(now); Ok(!k.NotInstalled && k.State == CheckState.Unknown && k.Penalty == 0 && k.FixAction == "app:Keys", "Keys installed, no status yet: unknown, no points, Open");
            Status("Keys", "{\"app\":\"Keys\",\"version\":\"2.7\",\"running\":true,\"locked\":true,\"items\":null}");
            k = Keys(now); Ok(k.State == CheckState.Unknown && k.Penalty == 0 && k.Line.Contains("2.7") && k.FixAction.EndsWith("/releases/latest"), "Keys 2.7 (no health field): unknown, asks for 2.8");
            Status("Keys", "{\"app\":\"Keys\",\"version\":\"2.8\",\"running\":true,\"locked\":true,\"health\":null}");
            k = Keys(now); Ok(k.State == CheckState.Unknown && k.Penalty == 0 && k.Line.Contains("Unlock"), "Keys 2.8 never unlocked (health null): unknown, unlock once");
            running.Add("Keys"); Status("Keys", Health(40, 1, 2, 0, "0", "0", now.AddMinutes(-5)));
            k = Keys(now); Ok(k.State == CheckState.Warn && k.Penalty == 9 && k.Line.Contains("2 reused passwords") && k.Line.Contains("1 weak password") && k.Line.StartsWith("Of your 40 logins"), "Keys running: 2 reused (-5), 1 weak (-4) = -9, warn");
            Status("Keys", Health(40, 1, 2, 1, "2", "3", now.AddMinutes(-5)));
            k = Keys(now); Ok(k.State == CheckState.Bad && k.Penalty == FamilyScore.KeysMax && k.Line.Contains("1 leaked password") && k.Line.Contains("2 logins on breached sites") && k.Line.Contains("3 sites that offer 2FA"), "Keys leaked + breached + reused + weak + 2FA: bad, capped at 12");
            Status("Keys", Health(40, 0, 0, 0, "null", "null", now.AddMinutes(-5)));
            k = Keys(now); Ok(k.State == CheckState.Good && k.Penalty == 0 && k.FixLabel == null, "Keys all healthy (lists not downloaded = null, not counted): good");
            running.Remove("Keys"); Status("Keys", Health(40, 1, 0, 0, "0", "0", now.AddDays(-40)));
            k = Keys(now); Ok(k.State == CheckState.Warn && k.Penalty == 4 && k.Line.Contains("refresh"), "Keys stopped, counts 40 days old (stale): still counted, asks to refresh");
            Status("Keys", Health(40, 5, 5, 5, "0", "0", now.AddDays(-120)));
            k = Keys(now); Ok(k.State == CheckState.Unknown && k.Penalty == 0, "Keys counts 4 months old: too stale to count");
            Status("Keys", "{\"app\":\"Keys\",\"health\":{\"logins\":9,\"weak\":\"ZQ Bank login\",\"reused\":\"https://zq.example\",\"leaked\":0,\"when\":\"" + T(now) + "\"}}");
            k = Keys(now); Ok(k.Penalty == 0 && !k.Line.Contains("ZQ") && !k.Line.Contains("zq.example"), "Keys: anything but numbers in health is ignored (never shown)");
            Status("Keys", "{ broken"); k = Keys(now); Ok(k.State == CheckState.Unknown && k.Penalty == 0, "Keys: broken status.json = unknown, no crash");
            Status("Keys", Health(0, 0, 0, 0, "0", "0", now)); k = Keys(now); Ok(k.State == CheckState.Good && k.Line.Contains("No logins"), "Keys: no logins yet = good");

            // Vault
            var v = Vault(now); Ok(v.NotInstalled && v.Penalty == 0 && v.FixAction == "url:" + FamilyScore.VaultUrl, "Vault missing: not installed, no points");
            Install("Vault"); running.Add("Vault");
            Func<string, string, string, string> vs = (games, check, copy) => "{\"app\":\"Vault\",\"version\":\"1.12\",\"updated\":\"" + T(now) + "\",\"running\":true,\"busy\":false,\"secondCopy\":" + copy + ",\"lastCheck\":{\"when\":null,\"damaged\":" + check + "},\"games\":[" + games + "]}";
            Func<string, DateTime?, bool, string> game = (n, t, off) => "{\"name\":\"" + n + "\",\"lastBackup\":" + (t == null ? "null" : "\"" + T(t.Value) + "\"") + ",\"versions\":3,\"off\":" + (off ? "true" : "false") + "}";
            Status("Vault", vs(game("Deadlock", now.AddHours(-2), false) + "," + game("Old Game", now.AddDays(-200), true), "0", "null"));
            v = Vault(now); Ok(v.State == CheckState.Good && v.Penalty == 0 && v.Line.Contains("2 hours ago") && v.Line.Contains("1 game"), "Vault running, fresh backup (a game switched off doesn't count): good");
            running.Remove("Vault");
            v = Vault(now); Ok(v.State == CheckState.Warn && v.Penalty == 2 && v.FixAction == "app:start:Vault" && v.Line.Contains("isn't running"), "Vault stopped: warn -2, Start Hallow Vault");
            Status("Vault", vs(game("Deadlock", now.AddDays(-3), false), "0", "null").Replace("\"updated\":\"" + T(now) + "\"", "\"updated\":\"" + T(now.AddDays(-3)) + "\""));
            v = Vault(now); Ok(v.State == CheckState.Warn && v.Line.Contains("isn't running"), "Vault stale (status.json says running, 3 days old, no pipe): treated as stopped");
            running.Add("Vault");
            Status("Vault", vs(game("Deadlock", now.AddDays(-20), false), "0", "null"));
            v = Vault(now); Ok(v.State == CheckState.Warn && v.Penalty == 3 && v.Line.Contains("2 weeks ago") && v.FixAction == "app:Vault", "Vault: last backup 20 days ago: warn -3");
            Status("Vault", vs(game("Deadlock", now.AddHours(-1), false), "2", "{\"reachable\":false,\"behind\":0,\"conflicts\":0}"));
            v = Vault(now); Ok(v.State == CheckState.Bad && v.Penalty == 8 && v.Line.Contains("2 backups failed") && v.Line.Contains("second-copy"), "Vault failing: damaged backups (-6) + unreachable copy (-3), capped at 8, bad");
            Status("Vault", vs(game("Deadlock", null, false), "0", "null"));
            v = Vault(now); Ok(v.Penalty == 3 && v.Line.Contains("No backups yet"), "Vault: games but no backup yet: -3");
            Status("Vault", vs("", "0", "null"));
            v = Vault(now); Ok(v.State == CheckState.Info && v.Penalty == 0, "Vault: no games found yet: info, no points");
            NoStatus("Vault"); v = Vault(now); Ok(v.State == CheckState.Unknown && v.Penalty == 0, "Vault installed, no status: unknown");

            // Assist
            var a = Assist(); Ok(a.NotInstalled && a.Penalty == 0 && a.FixAction == "url:" + FamilyScore.AssistUrl, "Assist missing: not installed");
            Install("Assist"); NoStatus("Assist"); a = Assist(); Ok(a.State == CheckState.Unknown && a.Penalty == 0, "Assist installed, no status: unknown");
            Status("Assist", "{\"app\":\"Assist\",\"version\":\"1.0\",\"running\":false,\"session\":\"none\",\"unattended\":true,\"relaySet\":true}");
            a = Assist(); Ok(a.State == CheckState.Info && a.Penalty == 0 && a.Line.Contains("Unattended access is on") && a.Line.Contains("make sure its password is strong") && a.FixAction == "app:Assist", "Assist stopped, unattended on: a line, no points");
            running.Add("Assist"); Status("Assist", "{\"app\":\"Assist\",\"running\":true,\"session\":\"connected\",\"unattended\":false}");
            a = Assist(); Ok(a.State == CheckState.Good && a.Line.Contains("off") && a.Line.Contains("connected right now"), "Assist running, unattended off, a session on: good + says so");
            Status("Assist", "{\"app\":\"Assist\",\"running\":true,\"session\":\"connected\",\"unattended\":false}"); running.Remove("Assist");
            a = Assist(); Ok(!a.Line.Contains("connected right now"), "Assist stale 'connected' while it isn't running: not claimed");
            // the whole probe
            var f = FamilyProbe.Read(Env());
            Ok(f.Keys.State == "stopped" && f.Vault.State == "running" && f.Assist.State == "stopped", "probe: states missing / running / stopped from exe + pipe (" + f.Keys.State + ", " + f.Vault.State + ", " + f.Assist.State + ")");
            var none = FamilyProbe.Read(new FamilyEnv { ProgramsDir = Path.Combine(Root, "nothing"), DataDir = x => Path.Combine(Root, "nothing"), Running = x => true, TempDir = Path.Combine(Root, "copies") });
            Ok(none.Keys.State == "missing" && none.Vault.State == "missing" && none.Assist.State == "missing" && none.Browsers.Count == 0, "probe: nothing installed = all missing (a pipe alone doesn't make it installed)");
        }

        // ---------------- Hallow Shield in fake browser profiles
        static string Hash(string f) { using (var s = SHA256.Create()) using (var r = File.OpenRead(f)) return BitConverter.ToString(s.ComputeHash(r)) + File.GetLastWriteTimeUtc(f).Ticks; }
        static void W(string f, string text) { Directory.CreateDirectory(Path.GetDirectoryName(f)); File.WriteAllText(f, text); }
        static string Js(string s) { return s.Replace("\\", "\\\\"); }
        static void Shield()
        {
            var unpacked = Path.Combine(Root, "src", "HallowShield", "extension");
            W(Path.Combine(unpacked, "manifest.json"), "{\"manifest_version\":3,\"name\":\"Hallow Shield\",\"version\":\"1.1\"}");
            var other = Path.Combine(Root, "src", "Other"); W(Path.Combine(other, "manifest.json"), "{\"name\":\"Some Other Blocker\",\"version\":\"9\"}");
            var chrome = Path.Combine(Root, "Browsers", "Chrome", "User Data");
            W(Path.Combine(chrome, "Local State"), "{}");
            W(Path.Combine(chrome, "Default", "Preferences"), "{\"profile\":{\"name\":\"Person 1\"}}");
            W(Path.Combine(chrome, "Default", "Secure Preferences"), "{\"extensions\":{\"settings\":{\"aaaabbbbccccddddeeeeffffgggghhhh\":{\"location\":4,\"path\":\"" + Js(unpacked) + "\",\"state\":1},\"ghbmnnjooekpmoecnnnilnnbdlolhkhi\":{\"location\":1,\"path\":\"ghbmnnjooekpmoecnnnilnnbdlolhkhi\\\\1.0_0\",\"manifest\":{\"name\":\"Google Docs Offline\",\"version\":\"1.0\"}}}}}");
            W(Path.Combine(chrome, "Profile 2", "Secure Preferences"), "{\"extensions\":{\"settings\":{\"x\":{\"location\":4,\"path\":\"" + Js(other) + "\"}}}}");
            W(Path.Combine(chrome, "Profile 3", "Preferences"), "{\"extensions\":{\"settings\":{\"y\":{\"location\":4,\"path\":\"" + Js(Path.Combine(Root, "deleted-folder")) + "\"}}}}");
            W(Path.Combine(chrome, "System Profile", "Secure Preferences"), "{\"extensions\":{\"settings\":{\"z\":{\"path\":\"" + Js(unpacked) + "\"}}}}");
            var edge = Path.Combine(Root, "Browsers", "Edge", "User Data");
            W(Path.Combine(edge, "Default", "Secure Preferences"), "{\"extensions\":{\"settings\":{\"e1\":{\"location\":4,\"path\":\"C:\\\\nowhere\",\"manifest\":{\"name\":\"Hallow Shield\",\"version\":\"1.0\"},\"disable_reasons\":[1]}}}}");
            var brave = Path.Combine(Root, "Browsers", "Brave", "User Data");
            W(Path.Combine(brave, "Default", "Preferences"), "{ this is not json");
            W(Path.Combine(brave, "Default", "Secure Preferences"), "{\"extensions\":{\"settings\":{}}}");
            var opera = Path.Combine(Root, "Browsers", "Opera Stable");
            W(Path.Combine(opera, "Preferences"), "{}");
            W(Path.Combine(opera, "Extensions", "operashieldid", "1.1_0", "manifest.json"), "{\"name\":\"Hallow Shield\",\"version\":\"1.1\"}");
            var browserFiles = Directory.GetFiles(Path.Combine(Root, "Browsers"), "*", SearchOption.AllDirectories).Concat(Directory.GetFiles(Path.Combine(Root, "src"), "*", SearchOption.AllDirectories)).ToList();
            var before = browserFiles.ToDictionary(x => x, Hash);
            List<BrowserFacts> bs;
            // Chrome's Default\Preferences held open with no sharing while Guard looks (a running browser): tolerated
            using (var held = new FileStream(Path.Combine(chrome, "Default", "Preferences"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            using (var held2 = new FileStream(Path.Combine(brave, "Default", "Secure Preferences"), FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                bs = FamilyProbe.Read(Env()).Browsers;
            Func<string, BrowserFacts> B = n => bs.First(x => x.Name == n);
            var c = B("Chrome");
            Ok(c.Present && c.Profiles == 3 && c.Found.Count == 1 && c.Found[0].Profile == "Default" && c.Found[0].Version == "1.1" && c.Found[0].Enabled, "Chrome: Shield (unpacked) found in Default with its version; another extension / a deleted unpacked folder / System Profile don't count");
            var e = B("Edge"); Ok(e.Found.Count == 1 && !e.Found[0].Enabled && e.Found[0].Version == "1.0", "Edge: Shield found from the stored manifest, switched off (disable_reasons)");
            var b = B("Brave"); Ok(b.Present && b.Found.Count == 0 && b.Profiles == 1, "Brave: broken Preferences + locked Secure Preferences = not found, no crash");
            var o = B("Opera"); Ok(o.Present && o.Found.Count == 1 && o.Found[0].Version == "1.1" && o.Found[0].Profile == "", "Opera (single profile): a packed copy in Extensions\\ is found");
            Ok(browserFiles.All(x => Hash(x) == before[x]), "the browser files are unchanged (contents and times)");
            Ok(!Directory.Exists(Path.Combine(Root, "copies")) || Directory.GetFiles(Path.Combine(Root, "copies")).Length == 0, "the copies Guard read are gone again");
            var sc = FamilyScore.ShieldCheck(bs);
            Ok(sc.State == CheckState.Warn && sc.Penalty == 2 && sc.Line.Contains("Chrome 1.1") && sc.Line.Contains("Opera 1.1") && sc.Line.Contains("Not in Brave") && sc.Line.Contains("switched off in Edge"), "Shield check: installed per browser with versions, not in Brave, off in Edge (-2): " + sc.Line);
            var good = FamilyScore.ShieldCheck(bs.Where(x => x.Name != "Edge").ToList()); Ok(good.State == CheckState.Good && good.Penalty == 0, "Shield on where installed: good");
            var none = FamilyScore.ShieldCheck(new List<BrowserFacts> { new BrowserFacts { Name = "Chrome", Present = true, Profiles = 1 } });
            Ok(none.NotInstalled && none.Penalty == 0 && none.Line.StartsWith("Not installed in Chrome") && none.FixAction == "url:" + FamilyScore.ShieldUrl, "Shield nowhere: not installed, no points, link");
            var nob = FamilyScore.ShieldCheck(new List<BrowserFacts> { new BrowserFacts { Name = "Chrome" } }); Ok(nob.NotInstalled && nob.Line.Contains("No Chrome, Edge, Brave or Opera"), "no Chromium browser at all: says so");
            Ok(ShieldScan.Browser("Nope", Path.Combine(Root, "no-such-browser"), false, Path.Combine(Root, "copies")).Present == false, "a browser folder that isn't there: not present");
        }

        // ---------------- score math and the to-do list
        static Check X(string id, CheckState s, int pen, string fix, string group = "apps", bool missing = false) { return new Check { Id = id, Title = id, State = s, Penalty = pen, FixLabel = fix == null ? null : "Fix", FixAction = fix, Group = group, NotInstalled = missing }; }
        static void Numbers()
        {
            var apps = new List<Check> { X("keys", CheckState.Warn, 9, "app:Keys"), X("vault", CheckState.Warn, 2, "app:start:Vault"), X("shield", CheckState.Info, 0, "url:x", "apps", true), X("assist", CheckState.Info, 0, "app:Assist") };
            Ok(FamilyScore.AppsScore(apps) == 89 && FamilyScore.Combined(95, apps) == 84, "apps 100-11 = 89; family = Windows 95 - 11 = 84");
            var heavy = new List<Check> { X("keys", CheckState.Bad, 12, "a"), X("vault", CheckState.Bad, 8, "b"), X("shield", CheckState.Warn, 2, "c"), X("other", CheckState.Bad, 9, "d") };
            Ok(FamilyScore.Combined(100, heavy) == 75 && FamilyScore.AppsScore(heavy) == 69, "the apps take off at most 25 from the family score");
            var missing = new List<Check> { X("keys", CheckState.Info, 0, "url:k", "apps", true), X("vault", CheckState.Info, 0, "url:v", "apps", true) };
            Ok(FamilyScore.AppsScore(missing) == null && FamilyScore.Combined(88, missing) == 88, "nothing installed: no apps score, family score = Windows score (missing apps never cost points)");
            Ok(FamilyScore.Combined(-1, apps) == -1 && FamilyScore.Combined(5, heavy) == 0, "not checked yet = -1; never below 0");
            var real = FamilyScore.Evaluate(new FamilyFacts { Browsers = { new BrowserFacts { Name = "Edge", Present = true, Profiles = 1 } } });
            Ok(real.Count == 4 && real.All(x => x.NotInstalled && x.Penalty == 0 && x.Group == "apps" && x.FixAction.StartsWith("url:https://github.com/Dom428/")), "an empty PC: 4 not-installed Hallow apps, no points, links to their GitHub pages");
            var win = new List<Check> { X("av", CheckState.Bad, 30, "windowsdefender://threatsettings", "windows"), X("secureboot", CheckState.Warn, 4, null, "windows"), X("update", CheckState.Warn, 5, "ms-settings:windowsupdate", "windows"), X("bitlocker", CheckState.Unknown, 0, "admin:bitlocker", "windows"), X("tamper", CheckState.Warn, 8, "x", "windows"), X("scan", CheckState.Warn, 5, "scan:quick", "windows") };
            var todo = FamilyScore.Todo(win.Concat(apps).Concat(missing));
            Ok(todo.Count == 5 && todo.Select(x => x.Id).SequenceEqual(new[] { "av", "keys", "tamper", "update", "scan" }), "to-do: top 5 by points, each with a button (" + string.Join(",", todo.Select(x => x.Id)) + ")");
            Ok(!todo.Any(x => x.NotInstalled || x.FixAction == null || x.Id == "bitlocker"), "to-do: never 'not installed', never without a button, never a 0-point unknown");
            Ok(FamilyScore.Todo(new[] { X("assist", CheckState.Info, 0, "app:Assist") }).Count == 0, "to-do: unattended access on is a line, not a to-do");
        }
    }
}
