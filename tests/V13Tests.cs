// Hallow Guard 1.3 tests: the quick scan while you're away (fake clock, idle time, power and game - and the stand-in MpCmdRun,
// never a real scan), ISO weeks, the leftovers snapshot and its diff (fake leftovers and listeners), the weekly report (fake
// checks, scans, threats and last week's report), its one Hub balloon (a fake Hub on the test pipe) and the new pipe commands
// on the test copy of the app.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;

namespace HallowGuard.Tests
{
    public static class V13Tests
    {
        static Action<bool, string> Ok;
        static string Root;

        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            Root = Path.Combine(Path.GetTempPath(), "HallowGuardV13Test" + Process.GetCurrentProcess().Id);
            try
            {
                if (Directory.Exists(Root)) Directory.Delete(Root, true); Directory.CreateDirectory(Root);
                WeekKeys(); Rules(); Scanner(); Settings(); Snapshot(); Report(); Balloon();
            }
            finally { try { Directory.Delete(Root, true); } catch { } }
        }

        // ---------------- ISO weeks
        static void WeekKeys()
        {
            Ok(Weeks.Key(new DateTime(2026, 11, 20)) == "2026-47" && Weeks.Key(new DateTime(2026, 11, 16)) == "2026-47" && Weeks.Key(new DateTime(2026, 11, 22, 23, 59, 0)) == "2026-47" && Weeks.Key(new DateTime(2026, 11, 23)) == "2026-48", "ISO week: Monday to Sunday is one week (2026-47)");
            Ok(Weeks.Key(new DateTime(2021, 1, 3)) == "2020-53" && Weeks.Key(new DateTime(2024, 12, 30)) == "2025-01" && Weeks.Key(new DateTime(2026, 1, 1)) == "2026-01" && Weeks.Key(new DateTime(2027, 1, 1)) == "2026-53", "ISO week across New Year (2020-53, 2025-01, 2026-53)");
            Ok(Weeks.Monday(new DateTime(2026, 11, 20, 15, 0, 0)) == new DateTime(2026, 11, 16) && Weeks.Valid("2026-47") && !Weeks.Valid("..\\x") && !Weeks.Valid("2026-4"), "Monday of the week; only yyyy-ww names are accepted");
        }

        // ---------------- when the away scan may start / must stop
        static void Rules()
        {
            var now = new DateTime(2026, 11, 18, 14, 0, 0); var away = TimeSpan.FromMinutes(12);
            Func<bool, string, TimeSpan, bool?, string, DateTime?, DateTime?, bool, bool, string> w = (on, every, idle, ac, busy, last, attempt, scanning, engine) => AwayScan.WhyNot(on, every, now, idle, ac, busy, last, attempt, scanning, engine);
            Ok(w(true, "weekly", away, true, null, now.AddDays(-8), null, false, true) == null, "away 12 min, plugged in, no game, last scan 8 days ago (weekly): go");
            Ok(w(false, "weekly", away, true, null, null, null, false, true) != null, "off: never");
            Ok(w(true, "weekly", TimeSpan.FromMinutes(9), true, null, null, null, false, true) == "you're using the PC" && w(true, "weekly", TimeSpan.FromMinutes(10), true, null, null, null, false, true) == null, "idle 9 min: wait; 10 min: go");
            Ok(w(true, "weekly", away, false, null, null, null, false, true) == "the PC is on battery" && w(true, "weekly", away, null, null, null, null, false, true).Contains("plugged in"), "on battery or unknown power: wait");
            Ok(w(true, "weekly", away, true, "a game is running", null, null, false, true) == "a game is running" && w(true, "weekly", away, true, "a full-screen app is open", null, null, false, true) == "a full-screen app is open", "a game or full-screen app: wait");
            Ok(w(true, "weekly", away, true, null, now.AddDays(-3), null, false, true).StartsWith("the last scan was") && w(true, "daily", away, true, null, now.AddDays(-3), null, false, true) == null && w(true, "daily", away, true, null, now.AddHours(-20), null, false, true) != null, "interval: 3 days ago is too recent for weekly, fine for daily; 20 h is too recent for daily");
            Ok(w(true, "weekly", away, true, null, null, now.AddMinutes(-30), false, true).Contains("less than an hour") && w(true, "weekly", away, true, null, null, now.AddMinutes(-61), false, true) == null, "stopped 30 min ago: not yet; 61 min: again");
            Ok(w(true, "weekly", away, true, null, null, null, true, true) == "a scan is running" && w(true, "weekly", away, true, null, null, null, false, false).Contains("wasn't found"), "another scan running, or no Defender scanner: wait");
            Ok(AwayScan.StopWhy(TimeSpan.FromSeconds(5), true, null) == "you came back" && AwayScan.StopWhy(TimeSpan.FromMinutes(20), true, "a game is running") == "a game is running" && AwayScan.StopWhy(TimeSpan.FromMinutes(20), false, null) == "the PC was unplugged" && AwayScan.StopWhy(TimeSpan.FromMinutes(20), true, null) == null && AwayScan.StopWhy(TimeSpan.FromMinutes(20), null, null) == null, "stop: you came back, a game started or unplugged; otherwise keep going");
        }

        // ---------------- the scanner with a fake clock, idle source, power and game, and a pretend scan
        static void Scanner()
        {
            var clock = new FakeClock { At = new DateTime(2026, 11, 18, 14, 0, 0) }; var idle = new FakeIdle(); var power = new FakePower { Value = true }; var busy = new FakeBusy();
            bool on = false, scanning = false; int starts = 0; var stops = new List<string>(); DateTime? last = clock.At.Value.AddDays(-9);
            var s = new AwayScanner(clock, idle, power, busy) { On = () => on, Every = () => "weekly", LastScan = () => last, Scanning = () => scanning, Start = () => { starts++; scanning = true; return null; }, Stop = why => { stops.Add(why); scanning = false; } };
            idle.Value = TimeSpan.FromMinutes(30);
            Ok(s.Tick() == "wait" && starts == 0 && s.Status == "it's off", "fake sources: off -> nothing starts");
            on = true; idle.Value = TimeSpan.FromSeconds(4);
            Ok(s.Tick() == "wait" && starts == 0, "in use -> nothing starts");
            idle.Value = TimeSpan.FromMinutes(11);
            Ok(s.Tick() == "started" && starts == 1 && s.Running && s.LastAttempt == clock.At, "away 11 min -> one quick scan starts");
            idle.Value = TimeSpan.FromMinutes(12);
            Ok(s.Tick() == "running" && starts == 1 && stops.Count == 0, "still away -> keeps going, no second scan");
            idle.Value = TimeSpan.FromSeconds(3);
            Ok(s.Tick() == "stopped" && stops.SequenceEqual(new[] { "you came back" }) && !s.Running, "input 3 s ago -> stopped: you came back");
            idle.Value = TimeSpan.FromMinutes(15);
            Ok(s.Tick() == "wait" && starts == 1 && s.Status.Contains("less than an hour"), "away again right after -> waits an hour");
            clock.At = clock.At.Value.AddMinutes(70);
            Ok(s.Tick() == "started" && starts == 2, "an hour later -> starts again");
            busy.Value = "a game is running";
            Ok(s.Tick() == "stopped" && stops.Last() == "a game is running", "a game starts -> stopped");
            clock.At = clock.At.Value.AddHours(2); busy.Value = null;
            Ok(s.Tick() == "started" && starts == 3, "game over, still away -> starts again");
            scanning = false; last = clock.At;
            Ok(s.Tick() == "finished" && !s.Running, "the scan finishes");
            Ok(s.Tick() == "wait" && s.Status.StartsWith("the last scan was") && starts == 3, "just scanned -> nothing until next week");
            power.Value = false; clock.At = clock.At.Value.AddDays(8);
            Ok(s.Tick() == "wait" && s.Status == "the PC is on battery", "a week later on battery -> waits");
        }

        static void Settings()
        {
            var d = new GuardSettings();
            Ok(!d.AwayScan && d.AwayEvery == "weekly" && d.ReportNotify, "defaults: away scan off (weekly), report balloon on");
            var old = "{\"UseHallowIcon\":true,\"WatchDownloads\":false,\"Scans\":[{\"Kind\":\"quick\",\"Result\":\"clean\"}]}";
            using (var m = new MemoryStream(Encoding.UTF8.GetBytes(old)))
            {
                var s = (GuardSettings)new DataContractJsonSerializer(typeof(GuardSettings)).ReadObject(m);
                Ok(s != null && !s.AwayScan && s.AwayEvery == "weekly" && s.ReportNotify && !s.Scans[0].Away, "a 1.2 settings file: away scan off, report balloon on, old scans not 'away'");
            }
        }

        // ---------------- "what changed since last week"
        static void Snapshot()
        {
            var lefts = new FakeLeftovers().Hunt(null); var net = FakeExtras.Network();
            List<string> kinds; var items = Snapshots.Take(lefts, net, out kinds);
            Ok(kinds.SequenceEqual(Snapshots.Kinds) && items.All(x => x.Kind != "Process" && x.Kind != "Hosts") && items.Count(x => x.Kind == "Listener") == net.Listeners.Count, "snapshot: startup, tasks, services, extensions, listeners (no processes or hosts lines)");
            Ok(items.All(x => x.Id.Length == 16 && x.Id.All(ch => "0123456789abcdef".IndexOf(ch) >= 0)) && items.All(x => x.Label.IndexOf(@"\Users\", StringComparison.OrdinalIgnoreCase) < 0), "snapshot: hashed 16-digit IDs, short names, no user folders");
            Ok(Snapshots.IdOf(lefts[0]) == Snapshots.IdOf(new FakeLeftovers().Hunt(null)[0]) && Snapshots.IdOf(lefts[0]) != Snapshots.IdOf(lefts[1]), "IDs are stable and distinct");
            Ok(Snapshots.Anon(@"C:\Users\Alex\AppData\Roaming\x.exe") == @"%USERPROFILE%\AppData\Roaming\x.exe", "anonymised: the user folder is taken out");
            Ok(Snapshots.Take(lefts, null, out kinds).All(x => x.Kind != "Listener") && !kinds.Contains("Listener") && Snapshots.Take(null, net, out kinds).All(x => x.Kind == "Listener") && kinds.SequenceEqual(new[] { "Listener" }), "a missing source isn't in the snapshot's kinds");
            // last week: SysHelper (suspicious startup) and MediaShare (listener) weren't there; OldGameLauncher was
            var before = items.Where(x => x.Label != "SysHelper" && x.Label != "MediaShare").ToList(); before.Add(new SnapItem { Kind = "Startup", Id = "00000000000000aa", Label = "OldGameLauncher" });
            var diff = Snapshots.Compare(before, Snapshots.Kinds.ToList(), items, Snapshots.Kinds.ToList(), "2026-46");
            Ok(diff.New.Count == 2 && diff.New[0].Label == "SysHelper" && diff.New[0].Suspicious && diff.New[1].Label == "MediaShare" && diff.NewSuspicious == 1 && diff.Removed.Count == 1 && diff.Removed[0].Label == "OldGameLauncher" && diff.Since == "2026-46", "diff: 2 new (the suspicious one first), 1 removed");
            var noNet = Snapshots.Compare(before.Where(x => x.Kind != "Listener").ToList(), new List<string> { "Startup", "Task", "Service", "Extension" }, items, Snapshots.Kinds.ToList(), "2026-46");
            Ok(noNet.New.Count == 1 && noNet.New[0].Label == "SysHelper", "diff: listeners missing last week aren't all 'new'");
            Ok(Snapshots.Compare(items, Snapshots.Kinds.ToList(), items, Snapshots.Kinds.ToList(), "x").New.Count == 0, "no change -> nothing new or removed");
            // files: save / load / the newest earlier week / only 8 kept
            var data = Path.Combine(Root, "snap");
            for (int i = 1; i <= 10; i++) Snapshots.Save(data, "2026-" + (30 + i).ToString("00"), items.Take(i).ToList(), Snapshots.Kinds.ToList(), new DateTime(2026, 8, 1).AddDays(7 * i));
            var files = Directory.GetFiles(Snapshots.Dir(data), "*.json");
            Ok(files.Length == 8 && !files.Any(f => f.EndsWith("2026-31.json") || f.EndsWith("2026-32.json")), "only the 8 newest snapshots are kept");
            Ok(Snapshots.Before(data, "2026-40") == "2026-39" && Snapshots.Before(data, "2026-50") == "2026-40" && Snapshots.Before(data, "2026-33") == null, "the newest snapshot from an earlier week");
            List<SnapItem> li; List<string> lk;
            Ok(Snapshots.Load(Path.Combine(Snapshots.Dir(data), "2026-40.json"), out li, out lk) && li.Count == 10 && lk.Count == 5 && li.Select(x => x.Id).SequenceEqual(items.Take(10).Select(x => x.Id)) && li.Count(x => x.Suspicious) == items.Take(10).Count(x => x.Suspicious), "snapshot round trip");
            var txt = File.ReadAllText(Path.Combine(Snapshots.Dir(data), "2026-40.json"));
            Ok(!txt.Contains("AppData") && !txt.Contains("Alex") && !txt.Contains(".exe"), "the snapshot file has no paths, user names or file names");
            Ok(!Snapshots.Load(Path.Combine(data, "missing.json"), out li, out lk), "a missing snapshot -> none");
        }

        // ---------------- the weekly report (fake checks, scans, threats, last week's report)
        static Check C(string id, string title, int pen, CheckState st = CheckState.Warn) { return new Check { Id = id, Title = title, Penalty = pen, State = st, FixAction = "x" }; }
        static void Report()
        {
            var now = new DateTime(2026, 11, 20, 19, 0, 0);
            var data = Path.Combine(Root, "rep");
            var prev = WeeklyReport.Build(new ReportInput { Now = now.AddDays(-7), Week = "2026-46", Score = 80, Checks = { C("updates", "Windows updates are waiting", 5), C("keys", "Hallow Keys: reused passwords", 6) } });
            Ok(J.Get(prev, "previousScore") == null && J.Get(prev, "delta") == null && J.Get(prev, "changes") == null && ((string)prev["summary"]).StartsWith("your first report"), "the first report: no 'then', no changes yet");
            WeeklyReport.Save(data, prev);
            var diff = new SnapDiff { Since = "2026-46", New = { new SnapItem { Kind = "Startup", Label = "SysHelper", Suspicious = true, Id = "a" }, new SnapItem { Kind = "Extension", Label = "Dark Reader (Chrome)", Id = "b" } }, Removed = { new SnapItem { Kind = "Task", Label = "Old Updater", Id = "c" } } };
            var scans = new List<ScanRecord> {
                new ScanRecord { Kind = "quick", Result = "clean", End = now.AddDays(-1).ToString("o"), Away = true },
                new ScanRecord { Kind = "download", Result = "threats", Threats = 1, End = now.AddDays(-3).ToString("o") },
                new ScanRecord { Kind = "quick", Result = "cancelled", End = now.AddDays(-2).ToString("o"), Away = true },
                new ScanRecord { Kind = "full", Result = "clean", End = now.AddDays(-12).ToString("o") } };
            var threats = new List<ThreatRecord> { new ThreatRecord { Name = "Trojan:Win32/Test", When = now.AddDays(-3) }, new ThreatRecord { Name = "Old", When = now.AddDays(-30) } };
            var checks = new List<Check> { C("keys", "Hallow Keys: reused passwords", 6), C("cfa", "Ransomware protection is off", 3), C("fine", "Firewall", 0, CheckState.Good), new Check { Id = "vault", Title = "Hallow Vault", NotInstalled = true, Penalty = 0, State = CheckState.Bad }, WeeklyReport.NewSuspiciousCheck(diff) };
            var r = WeeklyReport.Build(new ReportInput { Now = now, Week = "2026-47", Score = 88, Checks = checks, Scans = scans, Threats = threats, Changes = diff, Previous = WeeklyReport.Before(data, "2026-47") });
            Func<string, List<string>> titles = k => ((System.Collections.IEnumerable)r[k]).Cast<Dictionary<string, object>>().Select(x => (string)x["title"]).ToList();
            Ok((int)r["score"] == 88 && (int)r["previousScore"] == 80 && (int)r["delta"] == 8 && (string)r["previousWeek"] == "2026-46", "score then 80, now 88 (+8)");
            Ok(titles("fixed").SequenceEqual(new[] { "Windows updates are waiting" }) && titles("newIssues").SequenceEqual(new[] { "Ransomware protection is off" }) && titles("issues").Count == 2, "fixed: Windows updates; new: ransomware; not-installed apps, good checks and the 'new suspicious' item aren't issues");
            var sc = (Dictionary<string, object>)r["scans"];
            Ok((int)sc["total"] == 2 && (int)sc["away"] == 1 && (int)sc["stopped"] == 1 && (int)sc["withThreats"] == 1 && (int)sc["full"] == 0 && (int)sc["downloads"] == 1, "scans this week: 2 (1 while away), 1 stopped, the 12-day-old full scan not counted");
            Ok((int)r["threats"] == 1 && (int)((Dictionary<string, object>)r["changes"])["newSuspicious"] == 1 && (int)((Dictionary<string, object>)r["changes"])["removed"] == 1, "threats this week: 1; changes: 2 new (1 suspicious), 1 removed");
            Ok(WeeklyReport.Headline(r) == "Your weekly safety report: 88 (+8)", "headline: " + WeeklyReport.Headline(r));
            Ok((string)r["summary"] == "1 fixed, 1 new issue, 2 scans, 1 threat, 2 new items (1 suspicious).", "summary: " + r["summary"]);
            var text = WeeklyReport.Text(r);
            Ok(text.Contains("Safety score: 88") && text.Contains("last week 80 (+8)") && text.Contains("Fixed: Windows updates are waiting") && text.Contains("New issues: Ransomware protection is off") && text.Contains("1 while you were away") && text.Contains("+ SysHelper") && text.Contains("SUSPICIOUS") && text.Contains("- Old Updater"), "text summary: score, fixed, new, scans, changes");
            var brief = WeeklyReport.Brief(r); var bj = Family.Json(brief);
            Ok((int)brief["delta"] == 8 && (int)brief["fixed"] == 1 && (int)brief["newItems"] == 2 && (int)brief["newSuspicious"] == 1 && (int)brief["awayScans"] == 1 && !bj.Contains("SysHelper") && !bj.Contains("Ransomware protection"), "status lastReport: counts only, no names");
            WeeklyReport.Save(data, r);
            Ok(File.Exists(Path.Combine(WeeklyReport.Dir(data), "2026-47.json")) && File.Exists(Path.Combine(WeeklyReport.Dir(data), "2026-47.txt")) && File.ReadAllText(Path.Combine(WeeklyReport.Dir(data), "2026-47.txt")).Contains("\r\n"), "reports\\2026-47.json and .txt written");
            var list = WeeklyReport.List(data);
            Ok(list.Count == 2 && (string)list[0]["week"] == "2026-47" && WeeklyReport.WeeksIn(data).SequenceEqual(new[] { "2026-47", "2026-46" }) && WeeklyReport.Load(data, "..\\2026-47") == null, "past weeks newest first; bad names refused");
            var loaded = list[0]; var lb = WeeklyReport.Brief(loaded);
            Ok(WeeklyReport.Headline(loaded) == "Your weekly safety report: 88 (+8)" && (int)lb["fixed"] == 1 && (int)lb["scans"] == 2, "a report read back from disk gives the same headline and counts");
            // a worse week (negative delta survives the JSON round trip)
            var worse = WeeklyReport.Build(new ReportInput { Now = now.AddDays(7), Week = "2026-48", Score = 85, Checks = checks, Previous = WeeklyReport.Before(data, "2026-48") });
            WeeklyReport.Save(data, worse); var wl = WeeklyReport.Load(data, "2026-48");
            Ok(WeeklyReport.Headline(wl) == "Your weekly safety report: 85 (-3)" && Convert.ToInt32(WeeklyReport.Brief(wl)["delta"]) == -3, "a worse week: 85 (-3), also after reading it back");
            Ok(WeeklyReport.Text(wl).Contains("Threats Defender found this week: Windows didn't say"), "threats unknown -> says so (not 0)");
            var nc = WeeklyReport.NewSuspiciousCheck(diff);
            Ok(nc.Id == "new-suspicious" && nc.Penalty == 0 && nc.FixAction == "page:leftovers" && nc.State == CheckState.Bad && nc.Title == "New since last week: 1 suspicious startup item" && nc.Line.Contains("SysHelper") && WeeklyReport.NewSuspiciousCheck(new SnapDiff()) == null && WeeklyReport.NewSuspiciousCheck(null) == null, "to-do item for new suspicious items (no points, opens Leftovers)");
            var fake = FakeWeekly.Reports(now);
            Ok(fake.Count == 4 && fake.All(x => Weeks.Valid((string)x["week"])) && WeeklyReport.Headline(fake[0]).EndsWith("88 (+3)"), "made-up reports for --snap");
        }

        static void Balloon()
        {
            Ok(WeeklyReport.ShouldNotify(true, true, true, null, "2026-47", null), "balloon: setting on, notifications on, Hub showing, no game, not sent this week");
            Ok(!WeeklyReport.ShouldNotify(false, true, true, null, "2026-47", null) && !WeeklyReport.ShouldNotify(true, false, true, null, "2026-47", null) && !WeeklyReport.ShouldNotify(true, true, false, null, "2026-47", null), "no balloon: setting off, Windows notifications off, or Hub not running");
            Ok(!WeeklyReport.ShouldNotify(true, true, true, "a game is running", "2026-47", null) && !WeeklyReport.ShouldNotify(true, true, true, null, "2026-47", "2026-47"), "no balloon while gaming, and only one a week");
        }

        // ---------------- on the test copy of the app (test pipe names, fake sources, the stand-in MpCmdRun)
        static List<string> Lines(string f) { for (int i = 0; i < 10; i++) { try { return File.Exists(f) ? File.ReadAllLines(f).ToList() : new List<string>(); } catch { Thread.Sleep(50); } } return new List<string>(); }
        static Dictionary<string, object> Test(Dictionary<string, object> st) { return st == null ? null : st["test"] as Dictionary<string, object>; }
        static Dictionary<string, object> WaitFor(Func<Dictionary<string, object>> status, Func<Dictionary<string, object>, bool> cond, int ms = 10000)
        {
            Dictionary<string, object> st = null;
            for (int i = 0; i < ms / 200; i++) { st = status(); if (st != null && cond(st)) return st; Thread.Sleep(200); }
            return st;
        }
        public static void Pipe(Func<string, string> send, Func<Dictionary<string, object>> status, string dir, string mplog, Action<bool, string> ok)
        {
            // a fake Hallow Hub on the test pipe: its icon is "showing", it records every notify
            var hub = new List<string>();
            Family.Serve("Hub", line => { lock (hub) hub.Add(line); return line == "tray-host" ? "ok {\"on\":true,\"apps\":[\"Guard\"]}" : line.StartsWith("notify ") ? "ok" : "error unknown command"; });
            var st = status();
            ok(st != null && st.ContainsKey("lastReport") && st["lastReport"] == null && st.ContainsKey("awayScan") && !(bool)st["awayScan"] && (string)st["awayEvery"] == "weekly" && st.ContainsKey("changes") && st.ContainsKey("lastAwayScan"), "status (1.3): awayScan off (weekly), lastReport null, changes / lastAwayScan keys there");
            ok(send("report") == "error no report yet" && send("report ..\\x").StartsWith("error usage") && send("report 2020-01") == "error no report for 2020-01", "report: none yet; bad names refused");

            // ---- the quick scan while you're away
            var before = Lines(mplog).Count;
            ok(send("test-away-tick") == "ok wait - it's off", "away scan off by default: nothing happens");
            send("test-away on daily"); send("test-idle 60"); send("test-power ac"); send("test-busy off");
            ok(send("test-away-tick") == "ok wait - you're using the PC", "idle 1 min: waits (you're using the PC)");
            send("test-idle 900"); send("test-power battery");
            ok(send("test-away-tick") == "ok wait - the PC is on battery", "idle 15 min on battery: waits");
            send("test-power ac"); send("test-busy a game is running");
            ok(send("test-away-tick") == "ok wait - a game is running", "idle 15 min, a game running: waits");
            ok(Lines(mplog).Count == before, "nothing was started while waiting");
            send("test-busy off");
            var r = send("test-away-tick");
            ok(r == "ok started - scanning", "away 15 min, plugged in, no game, last scan 2 days ago (daily): the quick scan starts (" + r + ")");
            st = status();
            ok((bool)st["scanning"] && (string)st["scanKind"] == "quick" && (bool)Test(st)["jobAway"] && (bool)Test(st)["awayRunning"], "status: a quick scan while you're away is running");
            st = WaitFor(status, s => !(bool)s["scanning"]);
            ok((string)st["lastGuardScanKind"] == "quick" && (string)st["lastGuardScanResult"] == "clean" && st["lastAwayScan"] != null, "it finished clean (stand-in engine); lastAwayScan set");
            var ml = Lines(mplog).Skip(before).ToList();
            ok(ml.Any(l => l.StartsWith("-Scan -ScanType 1")) && ml.Any(l => l.Contains("priority=Idle")) && !ml.Any(l => l.Contains("priority=Normal")), "the engine got -Scan -ScanType 1 at Idle priority");
            ok(send("test-away-tick") == "ok finished - finished" && send("test-away-tick").StartsWith("ok wait - the last scan was"), "then nothing until tomorrow");
            // you come back / a game starts: a slow stand-in scan is stopped
            File.WriteAllText(Path.Combine(dir, "slow-quick"), "the stand-in waits 30 s for the quick scan");
            try
            {
                send("test-clock " + DateTime.Now.AddDays(2).ToString("o"));
                ok(send("test-away-tick") == "ok started - scanning", "two days later, away again: started");
                Thread.Sleep(700); send("test-idle 3");
                r = send("test-away-tick");
                ok(r.StartsWith("ok stopped") && r.Contains("you came back"), "input 3 s ago: stopped - " + r);
                Func<Dictionary<string, object>, bool> stopped = s => !(bool)s["scanning"] && ((string)Test(s)["lastMessage"] ?? "").Contains("you came back") && Lines(mplog).Skip(before).Any(l => l.StartsWith("-Cancel"));
                st = WaitFor(status, stopped, 15000);
                ok(stopped(st) && (string)Test(st)["jobResult"] == "cancelled", "the scan was cancelled (MpCmdRun -Cancel) and says why (" + Test(st)["lastMessage"] + ")");
                send("test-idle 900");
                ok(send("test-away-tick") == "ok wait - it was stopped less than an hour ago", "away again at once: waits an hour");
                send("test-clock " + DateTime.Now.AddDays(2).AddHours(2).ToString("o"));
                ok(send("test-away-tick") == "ok started - scanning", "two hours later: started again");
                Thread.Sleep(500); send("test-busy a game is running");
                r = send("test-away-tick");
                ok(r.StartsWith("ok stopped") && r.Contains("a game is running"), "a game starts: stopped - " + r);
                st = WaitFor(status, s => !(bool)s["scanning"]);
                ok(!(bool)st["scanning"] && (string)Test(st)["jobResult"] == "cancelled", "cancelled when the game started");
            }
            finally { File.Delete(Path.Combine(dir, "slow-quick")); send("test-busy off"); send("test-clock now"); send("test-idle 0"); send("test-away off"); }
            ok(!(bool)status()["awayScan"], "away scan off again");

            // ---- what changed + the weekly report
            var week = Weeks.Key(DateTime.Now); var prevWeek = Weeks.Key(DateTime.Now.AddDays(-7));
            List<string> kinds; var items = Snapshots.Take(new FakeLeftovers().Hunt(null), null, out kinds);
            items = items.Where(x => x.Label != "SysHelper").ToList(); items.Add(new SnapItem { Kind = "Startup", Id = "00000000000000aa", Label = "OldGameLauncher" });
            Snapshots.Save(dir, prevWeek, items, kinds, DateTime.Now.AddDays(-7));
            WeeklyReport.Save(dir, new Dictionary<string, object> { { "app", "Guard" }, { "week", prevWeek }, { "created", Family.Time(DateTime.Now.AddDays(-7)) }, { "score", 80 },
                { "issues", new List<object> { new Dictionary<string, object> { { "id", "oldthing" }, { "title", "An old problem" }, { "points", 4 } } } } });
            ok(send("test-report") == "ok", "test-report: hunt (made-up leftovers) then write the report");
            st = WaitFor(status, s => s["lastReport"] != null, 15000);
            var lr = st["lastReport"] as Dictionary<string, object>;
            int fs = Convert.ToInt32(st["familyScore"]);
            ok(lr != null && (string)lr["week"] == week && Convert.ToInt32(lr["score"]) == fs && Convert.ToInt32(lr["previousScore"]) == 80 && Convert.ToInt32(lr["delta"]) == fs - 80, "lastReport: this week, score = family score, then 80, delta " + (lr == null ? "?" : lr["delta"]));
            ok(lr != null && Convert.ToInt32(lr["fixed"]) == 1 && Convert.ToInt32(lr["newIssues"]) == Convert.ToInt32(lr["issues"]) && Convert.ToInt32(lr["newItems"]) == 1 && Convert.ToInt32(lr["removedItems"]) == 1 && Convert.ToInt32(lr["newSuspicious"]) == 1 && Convert.ToInt32(lr["awayScans"]) == 1, "lastReport: 1 fixed, new issues, 1 new (suspicious) + 1 removed leftover, 1 scan while away");
            var ch = st["changes"] as Dictionary<string, object>;
            ok(ch != null && (string)ch["since"] == prevWeek && Convert.ToInt32(ch["newSuspicious"]) == 1, "status changes: since last week, 1 new suspicious");
            var stNoTest = new Dictionary<string, object>(st); stNoTest.Remove("test"); var sj = Family.Json(stNoTest);
            ok(!sj.Contains("SysHelper") && !sj.Contains("OldGameLauncher") && !sj.Contains("An old problem"), "status.json: counts only - no item names or titles");
            var todo = ((System.Collections.IEnumerable)Test(st)["todoIds"]).Cast<object>().Select(x => x.ToString()).ToList();
            ok(todo.Count > 1 && todo[0] == "new-suspicious" && todo.Count <= 5, "to-do: the new suspicious item is first (" + string.Join(", ", todo) + ")");
            var jf = Path.Combine(dir, @"reports\" + week + ".json"); var tf = Path.Combine(dir, @"reports\" + week + ".txt");
            var tx = File.Exists(tf) ? File.ReadAllText(tf) : "";
            ok(File.Exists(jf) && tx.Contains("Fixed: An old problem") && tx.Contains("+ SysHelper") && tx.Contains("SUSPICIOUS") && tx.Contains("- OldGameLauncher"), "reports\\<week>.json and the text summary (fixed, new and removed items)");
            var rep = send("report");
            ok(rep != null && rep.StartsWith("ok {") && rep.Contains("\"week\":\"" + week + "\"") && rep.Contains("SysHelper"), "pipe: report -> this week's report");
            ok(send("report " + prevWeek).Contains("\"score\":80") && send("report list").Contains(week) && send("report list").Contains(prevWeek), "pipe: report <week> and report list");
            var snapTxt = File.Exists(Path.Combine(dir, @"snapshots\" + week + ".json")) ? File.ReadAllText(Path.Combine(dir, @"snapshots\" + week + ".json")) : null;
            ok(snapTxt != null && snapTxt.Contains("\"Listener\"") && !snapTxt.Contains("AppData") && !snapTxt.Contains(".exe"), "this week's snapshot written (with listeners), no paths or file names");
            // one Hub balloon
            List<string> notes = null;
            for (int i = 0; i < 30; i++) { lock (hub) notes = hub.Where(l => l.StartsWith("notify ")).ToList(); if (notes.Count > 0) break; Thread.Sleep(200); }
            var d = fs - 80; var head = "Your weekly safety report: " + fs + " (" + (d > 0 ? "+" + d : d.ToString()) + ")";
            ok(notes.Count == 1 && notes[0].StartsWith("notify Guard\t" + head + "\t") && notes[0].Contains("Open Hallow Guard > Reports."), "one Hub notify: " + (notes.Count > 0 ? notes[0].Replace("\t", " | ") : "none"));
            ok(Convert.ToInt32(Test(status())["reportBalloons"]) == 1, "test copy counted one report balloon");
            send("test-report"); Thread.Sleep(2500);
            lock (hub) notes = hub.Where(l => l.StartsWith("notify ")).ToList();
            ok(notes.Count == 1, "the report written again this week: no second balloon");
            ok(send("test-reload") == "ok" && Convert.ToInt32(((Dictionary<string, object>)status()["changes"])["new"]) == 1, "changes are read back from the snapshot files after a restart");
        }
    }
}
