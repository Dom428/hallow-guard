// Hallow Guard v1.3 - a quick scan while you're away (off by default), the weekly safety report and "what changed since last
// week" (a small snapshot of startup items, tasks, services, extensions and programs open to the network: hashed IDs and short
// names only - never file contents). Clock, idle time, power, "is a game running" and the snapshots all come in from outside,
// so every rule here is tested with fakes: tests never start a real scan.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace HallowGuard
{
    // ---------------- sources (the real ones read Windows; tests and the test copy use the fakes)
    public interface IClock { DateTime Now { get; } }
    public class RealClock : IClock { public DateTime Now { get { return DateTime.Now; } } }
    // a fixed time (unit tests) or the real time moved by an offset (the test copy, so recorded scans still line up)
    public class FakeClock : IClock { public DateTime? At; public TimeSpan Offset; public DateTime Now { get { return At ?? DateTime.Now + Offset; } } }

    public interface IIdleSource { TimeSpan Idle(); }
    // how long since the last mouse or keyboard input (GetLastInputInfo). Game controllers don't count - that's why a running
    // game or full-screen app is checked separately.
    public class WindowsIdle : IIdleSource
    {
        [StructLayout(LayoutKind.Sequential)] struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
        [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
        public TimeSpan Idle()
        {
            var li = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO)) };
            if (!GetLastInputInfo(ref li)) return TimeSpan.Zero;
            return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - li.dwTime));
        }
    }
    public class FakeIdle : IIdleSource { public TimeSpan Value; public TimeSpan Idle() { return Value; } }

    public interface IPowerSource { bool? OnAc(); }   // null = unknown
    public class WindowsPower : IPowerSource
    {
        [StructLayout(LayoutKind.Sequential)] struct SYSTEM_POWER_STATUS { public byte ACLineStatus, BatteryFlag, BatteryLifePercent, SystemStatusFlag; public int BatteryLifeTime, BatteryFullLifeTime; }
        [DllImport("kernel32.dll")] static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS s);
        public bool? OnAc() { SYSTEM_POWER_STATUS s; if (!GetSystemPowerStatus(out s)) return null; return s.ACLineStatus == 1 ? true : s.ACLineStatus == 0 ? false : (bool?)null; }
    }
    public class FakePower : IPowerSource { public bool? Value = true; public bool? OnAc() { return Value; } }

    // why the PC is busy (a game or a full-screen app), or null when it isn't
    public interface IBusySource { string Busy(); }
    public class WindowsBusy : IBusySource
    {
        public static readonly string[] Games = { "DeltaForceClient-Win64-Shipping", "Discovery-d" };
        [DllImport("shell32.dll")] static extern int SHQueryUserNotificationState(out int state);
        public string Busy()
        {
            foreach (var g in Games) { var ps = Process.GetProcessesByName(g); var any = ps.Length > 0; foreach (var p in ps) p.Dispose(); if (any) return "a game is running"; }
            try { int st; if (SHQueryUserNotificationState(out st) == 0 && (st == 2 || st == 3 || st == 4)) return "a full-screen app is open"; } catch { }
            // Hallow Hub knows which games are being played (its status.json, only while Hub runs)
            try
            {
                var hub = J.Parse(File.ReadAllText(Path.Combine(Family.DataDir("Hub"), "status.json")));
                var playing = J.Get(hub, "playing") as System.Collections.IEnumerable;
                if (J.Bool(hub, "running") == true && playing != null && playing.Cast<object>().Any()) return "a game is running";
            }
            catch { }
            return null;
        }
    }
    public class FakeBusy : IBusySource { public string Value; public string Busy() { return Value; } }

    // ---------------- the quick scan while you're away
    public static class AwayScan
    {
        public static readonly TimeSpan IdleNeeded = TimeSpan.FromMinutes(10);
        public static readonly TimeSpan BackWithin = TimeSpan.FromSeconds(30);   // input this recent while it runs = you're back
        public static readonly TimeSpan RetryAfter = TimeSpan.FromHours(1);      // a stopped scan isn't retried for an hour
        public static TimeSpan Every(string every) { return every == "daily" ? TimeSpan.FromDays(1) : TimeSpan.FromDays(7); }
        public static string EveryWord(string every) { return every == "daily" ? "daily" : "weekly"; }

        // null = start now; otherwise why not (shown in Settings)
        public static string WhyNot(bool on, string every, DateTime now, TimeSpan idle, bool? ac, string busy, DateTime? lastScan, DateTime? lastAttempt, bool scanning, bool engine)
        {
            if (!on) return "it's off";
            if (!engine) return "Microsoft Defender's scanner wasn't found";
            if (scanning) return "a scan is running";
            if (lastScan != null && now - lastScan.Value < Every(every)) return "the last scan was " + Score.Ago(lastScan, now);
            if (lastAttempt != null && now - lastAttempt.Value < RetryAfter) return "it was stopped less than an hour ago";
            if (busy != null) return busy;
            if (ac == false) return "the PC is on battery";
            if (ac == null) return "Windows doesn't say whether the PC is plugged in";
            if (idle < IdleNeeded) return "you're using the PC";
            return null;
        }
        // while it runs: null = keep going; otherwise why it stops
        public static string StopWhy(TimeSpan idle, bool? ac, string busy)
        {
            if (busy != null) return busy;
            if (idle < BackWithin) return "you came back";
            if (ac == false) return "the PC was unplugged";
            return null;
        }
    }

    // ticks about once a minute (every few seconds while its scan runs); the controller passes in how to start and stop a scan
    public class AwayScanner
    {
        readonly IClock clock; readonly IIdleSource idle; readonly IPowerSource power; readonly IBusySource busy;
        public Func<bool> On = () => false; public Func<string> Every = () => "weekly"; public Func<DateTime?> LastScan = () => null;
        public Func<bool> Scanning = () => false; public Func<bool> Engine = () => true;
        public Func<string> Start = () => "no scanner"; public Action<string> Stop = why => { };
        public bool Running; public DateTime? LastAttempt; public string Status = "it's off"; public string LastStop;
        public AwayScanner(IClock clock, IIdleSource idle, IPowerSource power, IBusySource busy) { this.clock = clock; this.idle = idle; this.power = power; this.busy = busy; }

        // "wait", "started", "running", "stopped", "finished" or "error"
        public string Tick()
        {
            var now = clock.Now;
            if (Running)
            {
                if (!Scanning()) { Running = false; Status = "finished"; return "finished"; }
                var why = AwayScan.StopWhy(idle.Idle(), power.OnAc(), busy.Busy());
                if (why == null) return "running";
                Running = false; LastStop = why; Status = "stopped - " + why; Stop(why); return "stopped";
            }
            if (!On()) { Status = "it's off"; return "wait"; }
            var w = AwayScan.WhyNot(true, Every(), now, idle.Idle(), power.OnAc(), busy.Busy(), LastScan(), LastAttempt, Scanning(), Engine());
            if (w != null) { Status = w; return "wait"; }
            LastAttempt = now;
            var err = Start();
            if (err != null) { Status = err; return "error"; }
            Running = true; Status = "scanning"; return "started";
        }
    }

    // ---------------- ISO weeks: report files are named <yyyy-ww>
    public static class Weeks
    {
        public static string Key(DateTime d)
        {
            int dow = ((int)d.DayOfWeek + 6) % 7;            // Monday = 0
            var thu = d.Date.AddDays(3 - dow);               // the week belongs to the year its Thursday is in
            return thu.Year.ToString("0000") + "-" + ((thu.DayOfYear - 1) / 7 + 1).ToString("00");
        }
        public static DateTime Monday(DateTime d) { return d.Date.AddDays(-(((int)d.DayOfWeek + 6) % 7)); }
        public static bool Valid(string key) { return key != null && Regex.IsMatch(key, @"^\d{4}-\d{2}$"); }
        public static string Nice(string key) { return Valid(key) ? "week " + int.Parse(key.Substring(5)) + " of " + key.Substring(0, 4) : key; }
    }

    // ---------------- "what changed since last week": a small snapshot
    public class SnapItem { public string Kind, Id, Label; public bool Suspicious; }
    public class SnapDiff
    {
        public string Since;   // the week the snapshot compared against
        public List<SnapItem> New = new List<SnapItem>(), Removed = new List<SnapItem>();
        public int NewSuspicious { get { return New.Count(x => x.Suspicious); } }
    }
    public static class Snapshots
    {
        public static readonly string[] Kinds = { "Startup", "Task", "Service", "Extension", "Listener" };
        public static string KindWord(string k, int n)
        {
            switch (k)
            {
                case "Startup": return n == 1 ? "startup item" : "startup items";
                case "Task": return n == 1 ? "scheduled task" : "scheduled tasks";
                case "Service": return n == 1 ? "service" : "services";
                case "Extension": return n == 1 ? "browser extension" : "browser extensions";
                case "Listener": return n == 1 ? "program open to the network" : "programs open to the network";
            }
            return k.ToLowerInvariant();
        }
        // a stable ID that doesn't spell out paths: SHA-256 of kind | what it runs (or its name), first 16 hex digits
        public static string HashId(string kind, string key)
        {
            using (var sha = SHA256.Create())
            {
                var h = sha.ComputeHash(Encoding.UTF8.GetBytes(kind + "|" + (key ?? "").Trim().ToLowerInvariant()));
                return string.Concat(h.Take(8).Select(b => b.ToString("x2")));
            }
        }
        // short names only, with the user's own folder and name taken out
        public static string Anon(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            var prof = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(prof)) s = Regex.Replace(s, Regex.Escape(prof), "%USERPROFILE%", RegexOptions.IgnoreCase);
            s = Regex.Replace(s, @"[A-Za-z]:\\Users\\[^\\]+", "%USERPROFILE%", RegexOptions.IgnoreCase);
            var user = Environment.UserName;
            if (!string.IsNullOrEmpty(user) && user.Length >= 3) s = Regex.Replace(s, @"\b" + Regex.Escape(user) + @"\b", "<user>", RegexOptions.IgnoreCase);
            return s.Length > 80 ? s.Substring(0, 80) : s;
        }
        public static string IdOf(Leftover l)
        {
            var key = l.Kind == "Extension" ? l.Detail ?? l.Name : (l.Kind == "Service" ? l.Where + "|" : "") + (l.File ?? l.Detail ?? l.Name) + "|" + l.Name;
            return HashId(l.Kind, key);
        }
        public static string IdOf(Listener l) { return HashId("Listener", l.Path ?? l.Name); }

        // leftovers: Startup / Task / Service / Extension (running processes and hosts lines come and go, so they're left out);
        // listeners from the Network page. kinds = what this snapshot covers (a missing source isn't "everything removed").
        public static List<SnapItem> Take(List<Leftover> leftovers, NetSnapshot net, out List<string> kinds)
        {
            var items = new List<SnapItem>(); kinds = new List<string>();
            if (leftovers != null)
            {
                var lk = new[] { "Startup", "Task", "Service", "Extension" }; kinds.AddRange(lk);
                foreach (var l in leftovers.Where(x => lk.Contains(x.Kind)))
                    items.Add(new SnapItem { Kind = l.Kind, Id = IdOf(l), Label = Anon(l.Kind == "Extension" ? l.Name + " (" + l.Where + ")" : l.Name), Suspicious = l.V == Verdict.Suspicious });
            }
            if (net != null && net.Error == null)
            {
                kinds.Add("Listener");
                foreach (var l in net.Listeners) items.Add(new SnapItem { Kind = "Listener", Id = IdOf(l), Label = Anon(l.Name), Suspicious = l.V == Verdict.Suspicious });
            }
            return items.GroupBy(x => x.Id).Select(g => g.First()).ToList();
        }
        public static SnapDiff Compare(List<SnapItem> before, List<string> beforeKinds, List<SnapItem> now, List<string> nowKinds, string since)
        {
            var both = new HashSet<string>((beforeKinds ?? new List<string>()).Intersect(nowKinds ?? new List<string>()));
            var b = new HashSet<string>(before.Where(x => both.Contains(x.Kind)).Select(x => x.Id)); var n = new HashSet<string>(now.Where(x => both.Contains(x.Kind)).Select(x => x.Id));
            return new SnapDiff
            {
                Since = since,
                New = now.Where(x => both.Contains(x.Kind) && !b.Contains(x.Id)).OrderBy(x => x.Suspicious ? 0 : 1).ThenBy(x => Array.IndexOf(Kinds, x.Kind)).ThenBy(x => x.Label).ToList(),
                Removed = before.Where(x => both.Contains(x.Kind) && !n.Contains(x.Id)).OrderBy(x => Array.IndexOf(Kinds, x.Kind)).ThenBy(x => x.Label).ToList()
            };
        }

        // files: <data>\snapshots\<yyyy-ww>.json - this week's is updated after each look; the 8 newest are kept
        public static string Dir(string data) { return Path.Combine(data, "snapshots"); }
        public static void Save(string data, string week, List<SnapItem> items, List<string> kinds, DateTime when)
        {
            var d = new Dictionary<string, object> { { "week", week }, { "taken", Family.Time(when) }, { "kinds", kinds },
                { "items", items.Select(x => new Dictionary<string, object> { { "k", x.Kind }, { "id", x.Id }, { "n", x.Label }, { "s", x.Suspicious } }).ToList() } };
            Atomic(Path.Combine(Dir(data), week + ".json"), Family.Json(d));
            try { foreach (var f in Directory.GetFiles(Dir(data), "*.json").Where(f => Weeks.Valid(Path.GetFileNameWithoutExtension(f))).OrderByDescending(f => f).Skip(8)) File.Delete(f); } catch { }
        }
        public static bool Load(string file, out List<SnapItem> items, out List<string> kinds)
        {
            items = new List<SnapItem>(); kinds = new List<string>();
            var d = File.Exists(file) ? J.Parse(SafeRead(file)) : null; if (d == null) return false;
            var k = J.Get(d, "kinds") as System.Collections.IEnumerable; if (k != null) foreach (var x in k) if (x is string) kinds.Add((string)x);
            var it = J.Get(d, "items") as System.Collections.IEnumerable;
            if (it != null) foreach (var o in it) { var x = o as Dictionary<string, object>; if (x == null || J.Str(x, "id") == null) continue; items.Add(new SnapItem { Kind = J.Str(x, "k"), Id = J.Str(x, "id"), Label = J.Str(x, "n"), Suspicious = J.Bool(x, "s") == true }); }
            return true;
        }
        // the newest snapshot from an earlier week than this one (null = none yet)
        public static string Before(string data, string week)
        {
            try { return Directory.GetFiles(Dir(data), "*.json").Select(Path.GetFileNameWithoutExtension).Where(w => Weeks.Valid(w) && string.CompareOrdinal(w, week) < 0).OrderByDescending(w => w).FirstOrDefault(); }
            catch { return null; }
        }
        internal static string SafeRead(string f) { try { return File.ReadAllText(f); } catch { return null; } }
        internal static void Atomic(string file, string text)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file));
            var tmp = file + ".tmp"; File.WriteAllText(tmp, text, new UTF8Encoding(false));
            for (int i = 0; ; i++) { try { if (File.Exists(file)) File.Replace(tmp, file, null); else File.Move(tmp, file); break; } catch { if (i >= 5) throw; Thread.Sleep(50); } }
        }
    }

    // ---------------- the weekly safety report: <data>\reports\<yyyy-ww>.json and .txt
    public class ReportInput
    {
        public DateTime Now; public string Week; public int Score = -1;
        public List<Check> Checks = new List<Check>();               // every check (Windows, Hallow apps, Network & browsers)
        public List<ScanRecord> Scans = new List<ScanRecord>();
        public DateTime? DefenderQuick, DefenderFull;
        public List<ThreatRecord> Threats;                          // null = Windows didn't say
        public SnapDiff Changes;
        public Dictionary<string, object> Previous;                 // last week's report (null = the first one)
    }
    public static class WeeklyReport
    {
        public static string Dir(string data) { return Path.Combine(data, "reports"); }
        static DateTime? T(string s) { DateTime t; return DateTime.TryParse(s, null, DateTimeStyles.RoundtripKind, out t) ? t : (DateTime?)null; }
        static int N(Dictionary<string, object> d, string k) { return J.Int(d, k) ?? 0; }
        static List<Dictionary<string, object>> L(Dictionary<string, object> d, string k)
        {
            var r = new List<Dictionary<string, object>>(); var v = J.Get(d, k) as System.Collections.IEnumerable;
            if (v != null && !(v is string)) foreach (var o in v) if (o is Dictionary<string, object>) r.Add((Dictionary<string, object>)o);
            return r;
        }
        public static bool IsIssue(Check c) { return c != null && !c.NotInstalled && c.Id != "new-suspicious" && (c.Penalty > 0 || c.State == CheckState.Bad || c.State == CheckState.Warn); }

        public static Dictionary<string, object> Build(ReportInput i)
        {
            var prev = i.Previous;
            var since = i.Now.AddDays(-7);
            var pc = prev == null ? null : T(J.Str(prev, "created"));
            if (pc != null && pc < i.Now && (i.Now - pc.Value).TotalDays <= 35) since = pc.Value;
            var issues = i.Checks.Where(IsIssue).GroupBy(c => c.Id).Select(g => g.First()).OrderByDescending(c => c.Penalty).ToList();
            var prevIssues = prev == null ? new List<Dictionary<string, object>>() : L(prev, "issues");
            var prevIds = new HashSet<string>(prevIssues.Select(x => J.Str(x, "id")).Where(x => x != null));
            var nowIds = new HashSet<string>(issues.Select(c => c.Id));
            Func<Check, Dictionary<string, object>> one = c => new Dictionary<string, object> { { "id", c.Id }, { "title", c.Title }, { "points", c.Penalty } };
            int? prevScore = prev == null ? null : J.Int(prev, "score");
            // scans in the window (Hallow Guard's, plus Defender's own newest quick / full scan when it's in the window)
            var scans = i.Scans.Where(s => { var e = T(s.End); return e != null && e >= since && e <= i.Now; }).ToList();
            var done = scans.Where(s => s.Result == "clean" || s.Result == "threats").ToList();
            var scanD = new Dictionary<string, object> {
                { "total", done.Count }, { "quick", done.Count(s => s.Kind == "quick") }, { "full", done.Count(s => s.Kind == "full") },
                { "custom", done.Count(s => s.Kind == "custom") }, { "downloads", done.Count(s => s.Kind == "download") }, { "away", done.Count(s => s.Away) },
                { "stopped", scans.Count(s => s.Result == "cancelled") }, { "withThreats", done.Count(s => s.Result == "threats") },
                { "defenderQuick", i.DefenderQuick != null && i.DefenderQuick >= since ? Family.Time(i.DefenderQuick.Value) : null },
                { "defenderFull", i.DefenderFull != null && i.DefenderFull >= since ? Family.Time(i.DefenderFull.Value) : null } };
            int? threats = i.Threats == null ? null : (int?)i.Threats.Count(t => t.When != null && t.When >= since && t.When <= i.Now);
            Dictionary<string, object> ch = null;
            if (i.Changes != null)
            {
                Func<SnapItem, Dictionary<string, object>> it = x => new Dictionary<string, object> { { "kind", x.Kind }, { "name", x.Label }, { "suspicious", x.Suspicious } };
                ch = new Dictionary<string, object> { { "since", i.Changes.Since }, { "new", i.Changes.New.Count }, { "removed", i.Changes.Removed.Count }, { "newSuspicious", i.Changes.NewSuspicious },
                    { "newItems", i.Changes.New.Take(30).Select(it).ToList() }, { "removedItems", i.Changes.Removed.Take(30).Select(it).ToList() } };
            }
            var r = new Dictionary<string, object> {
                { "app", "Guard" }, { "version", Program.Version }, { "week", i.Week }, { "created", Family.Time(i.Now) }, { "since", Family.Time(since) },
                { "score", i.Score >= 0 ? (object)i.Score : null }, { "scoreLabel", i.Score >= 0 ? Score.Label(i.Score) : null },
                { "previousScore", prevScore }, { "previousWeek", prev == null ? null : J.Str(prev, "week") },
                { "delta", prevScore != null && i.Score >= 0 ? (object)(i.Score - prevScore.Value) : null },
                { "fixed", prevIssues.Where(x => J.Str(x, "id") != null && !nowIds.Contains(J.Str(x, "id"))).Select(x => new Dictionary<string, object> { { "id", J.Str(x, "id") }, { "title", J.Str(x, "title") } }).ToList() },
                { "newIssues", prev == null ? new List<Dictionary<string, object>>() : issues.Where(c => !prevIds.Contains(c.Id)).Select(one).ToList() },
                { "issues", issues.Select(one).ToList() },
                { "scans", scanD }, { "threats", threats }, { "changes", ch } };
            r["summary"] = Line(r);
            return r;
        }
        public static string Delta(Dictionary<string, object> r) { var raw = J.Get(r, "delta"); if (raw == null) return null; var n = Convert.ToInt32(raw); return n > 0 ? "+" + n : n.ToString(); }
        // the balloon's title: "Your weekly safety report: 88 (+3)"
        public static string Headline(Dictionary<string, object> r)
        {
            var s = J.Int(r, "score"); var d = Delta(r);
            return "Your weekly safety report: " + (s == null ? "-" : s.ToString()) + (d == null ? "" : " (" + d + ")");
        }
        static string P(int n, string one, string many) { return n + " " + (n == 1 ? one : many); }
        // one short line: "1 fixed, 1 new issue, 3 scans, no threats, 2 new items (1 suspicious)."
        public static string Line(Dictionary<string, object> r)
        {
            var parts = new List<string>();
            int fx = L(r, "fixed").Count, ni = L(r, "newIssues").Count;
            if (J.Get(r, "previousScore") == null) parts.Add("your first report"); else { parts.Add(fx + " fixed"); parts.Add(P(ni, "new issue", "new issues")); }
            var sc = J.Dict(r, "scans"); parts.Add(P(sc == null ? 0 : N(sc, "total"), "scan", "scans"));
            var th = J.Int(r, "threats"); if (J.Get(r, "threats") != null) parts.Add(th == 0 ? "no threats" : P(th ?? 0, "threat", "threats"));
            var ch = J.Dict(r, "changes");
            if (ch != null) { int n = N(ch, "new"), s = N(ch, "newSuspicious"); parts.Add(P(n, "new item", "new items") + (s > 0 ? " (" + s + " suspicious)" : "")); }
            return string.Join(", ", parts) + ".";
        }
        public static string Text(Dictionary<string, object> r)
        {
            var sb = new StringBuilder();
            var since = T(J.Str(r, "since")); var created = T(J.Str(r, "created"));
            sb.AppendLine("Hallow Guard - weekly safety report, " + Weeks.Nice(J.Str(r, "week")) + (since != null && created != null ? " (" + since.Value.ToString("d MMM", CultureInfo.InvariantCulture) + " - " + created.Value.ToString("d MMM yyyy", CultureInfo.InvariantCulture) + ")" : ""));
            sb.AppendLine();
            var s = J.Int(r, "score"); var ps = J.Int(r, "previousScore");
            sb.AppendLine("Safety score: " + (s == null ? "not checked" : s + " (" + J.Str(r, "scoreLabel") + ")") + (ps == null ? " - your first report" : " - last week " + ps + " (" + Delta(r) + ")"));
            var fx = L(r, "fixed"); var ni = L(r, "newIssues"); var all = L(r, "issues");
            if (ps != null) { sb.AppendLine("Fixed: " + (fx.Count == 0 ? "nothing" : string.Join(", ", fx.Select(x => J.Str(x, "title"))))); sb.AppendLine("New issues: " + (ni.Count == 0 ? "none" : string.Join(", ", ni.Select(x => J.Str(x, "title"))))); }
            sb.AppendLine("Still to do: " + (all.Count == 0 ? "nothing" : string.Join(", ", all.Take(6).Select(x => J.Str(x, "title"))) + (all.Count > 6 ? " and " + (all.Count - 6) + " more" : "")));
            var sc = J.Dict(r, "scans");
            if (sc != null)
            {
                var kinds = new List<string>();
                if (N(sc, "quick") > 0) kinds.Add(P(N(sc, "quick"), "quick", "quick") + (N(sc, "away") > 0 ? " (" + N(sc, "away") + " while you were away)" : ""));
                if (N(sc, "full") > 0) kinds.Add(N(sc, "full") + " full"); if (N(sc, "custom") > 0) kinds.Add(N(sc, "custom") + " file/folder"); if (N(sc, "downloads") > 0) kinds.Add(P(N(sc, "downloads"), "download", "downloads"));
                sb.AppendLine("Scans by Hallow Guard: " + N(sc, "total") + (kinds.Count > 0 ? " - " + string.Join(", ", kinds) : "") + (N(sc, "withThreats") > 0 ? ", " + N(sc, "withThreats") + " found something" : N(sc, "total") > 0 ? ", nothing found" : ""));
                if (J.Str(sc, "defenderQuick") != null || J.Str(sc, "defenderFull") != null) sb.AppendLine("Defender also scanned on its own this week.");
            }
            sb.AppendLine("Threats Defender found this week: " + (J.Get(r, "threats") == null ? "Windows didn't say" : J.Int(r, "threats").ToString()));
            var ch = J.Dict(r, "changes");
            if (ch == null) sb.AppendLine("What changed: this is the first look - changes show from next week.");
            else
            {
                sb.AppendLine("What changed since " + Weeks.Nice(J.Str(ch, "since")) + ": " + P(N(ch, "new"), "new item", "new items") + ", " + N(ch, "removed") + " removed");
                foreach (var x in L(ch, "newItems")) sb.AppendLine("  + " + J.Str(x, "name") + " - " + Snapshots.KindWord(J.Str(x, "kind") ?? "", 1) + (J.Bool(x, "suspicious") == true ? "  (SUSPICIOUS - look at it in Leftovers)" : ""));
                foreach (var x in L(ch, "removedItems")) sb.AppendLine("  - " + J.Str(x, "name") + " - " + Snapshots.KindWord(J.Str(x, "kind") ?? "", 1));
            }
            sb.AppendLine();
            sb.AppendLine("Made by Hallow Guard " + J.Str(r, "version") + " on this PC. Nothing was sent anywhere.");
            return sb.ToString();
        }
        // what status.json carries (counts only - no names): "lastReport"
        public static Dictionary<string, object> Brief(Dictionary<string, object> r)
        {
            if (r == null) return null;
            var sc = J.Dict(r, "scans"); var ch = J.Dict(r, "changes");
            return new Dictionary<string, object> { { "week", J.Str(r, "week") }, { "created", J.Str(r, "created") }, { "score", J.Int(r, "score") }, { "previousScore", J.Int(r, "previousScore") },
                { "delta", J.Get(r, "delta") == null ? null : (object)Convert.ToInt32(J.Get(r, "delta")) }, { "fixed", L(r, "fixed").Count }, { "newIssues", L(r, "newIssues").Count }, { "issues", L(r, "issues").Count },
                { "scans", sc == null ? 0 : N(sc, "total") }, { "awayScans", sc == null ? 0 : N(sc, "away") }, { "threats", J.Int(r, "threats") },
                { "newItems", ch == null ? null : (object)N(ch, "new") }, { "removedItems", ch == null ? null : (object)N(ch, "removed") }, { "newSuspicious", ch == null ? null : (object)N(ch, "newSuspicious") },
                { "headline", Headline(r) }, { "summary", J.Str(r, "summary") } };
        }
        public static void Save(string data, Dictionary<string, object> r)
        {
            var w = J.Str(r, "week"); if (!Weeks.Valid(w)) throw new ArgumentException("bad week");
            Snapshots.Atomic(Path.Combine(Dir(data), w + ".json"), Family.Json(r));
            Snapshots.Atomic(Path.Combine(Dir(data), w + ".txt"), Text(r).Replace("\n", "\r\n").Replace("\r\r\n", "\r\n"));
        }
        public static Dictionary<string, object> Load(string data, string week)
        {
            if (!Weeks.Valid(week)) return null;
            var f = Path.Combine(Dir(data), week + ".json");
            return File.Exists(f) ? J.Parse(Snapshots.SafeRead(f)) : null;
        }
        public static List<string> WeeksIn(string data)
        {
            try { return Directory.GetFiles(Dir(data), "*.json").Select(Path.GetFileNameWithoutExtension).Where(Weeks.Valid).OrderByDescending(w => w).ToList(); }
            catch { return new List<string>(); }
        }
        public static List<Dictionary<string, object>> List(string data, int max = 26) { return WeeksIn(data).Take(max).Select(w => Load(data, w)).Where(x => x != null).ToList(); }
        public static Dictionary<string, object> Before(string data, string week) { var w = WeeksIn(data).FirstOrDefault(x => string.CompareOrdinal(x, week) < 0); return w == null ? null : Load(data, w); }

        // one balloon per week through Hallow Hub - only when Hub's icon is showing, notifications are on and nothing's being played
        public static bool ShouldNotify(bool settingOn, bool toastsOn, bool hubShowing, string busy, string week, string lastNotified)
        {
            return settingOn && toastsOn && hubShowing && busy == null && week != null && week != lastNotified;
        }
        // Windows' own "Notifications" switch (Settings > System > Notifications)
        public static bool WindowsToastsOn()
        {
            try { using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\PushNotifications")) { var v = k == null ? null : k.GetValue("ToastEnabled"); return !(v is int) || (int)v != 0; } }
            catch { return true; }
        }

        // the "new suspicious" to-do item (top of the list; it costs no points - it asks you to look)
        public static Check NewSuspiciousCheck(SnapDiff d)
        {
            if (d == null || d.NewSuspicious == 0) return null;
            var s = d.New.Where(x => x.Suspicious).ToList();
            var kinds = s.GroupBy(x => x.Kind).Select(g => Snapshots.KindWord(g.Key, g.Count())).ToList();
            return new Check { Id = "new-suspicious", Group = "more", State = CheckState.Bad, Penalty = 0, FixLabel = "Review", FixAction = "page:leftovers",
                Title = "New since last week: " + s.Count + " suspicious " + (kinds.Count == 1 ? kinds[0] : "items"),
                Line = string.Join(", ", s.Take(3).Select(x => x.Label)) + (s.Count > 3 ? " and " + (s.Count - 3) + " more" : "") + " - appeared since " + Weeks.Nice(d.Since) + ". Have a look in Leftovers." };
        }
    }

    // made-up reports and changes for --snap pictures
    public static class FakeWeekly
    {
        public static SnapDiff Changes()
        {
            return new SnapDiff { Since = Weeks.Key(DateTime.Now.AddDays(-7)),
                New = { new SnapItem { Kind = "Startup", Label = "SysHelper", Suspicious = true, Id = Snapshots.HashId("Startup", "syshelper") }, new SnapItem { Kind = "Task", Label = "Coupon Finder Update", Suspicious = true, Id = Snapshots.HashId("Task", "coupon") },
                        new SnapItem { Kind = "Extension", Label = "Dark Reader (Chrome)", Id = Snapshots.HashId("Extension", "dark") } },
                Removed = { new SnapItem { Kind = "Startup", Label = "OldGameLauncher", Id = "r1" }, new SnapItem { Kind = "Listener", Label = "MediaShare", Id = "r2" } } };
        }
        public static List<Dictionary<string, object>> Reports(DateTime now)
        {
            var l = new List<Dictionary<string, object>>(); Dictionary<string, object> prev = null;
            var scores = new[] { 74, 81, 85, 88 };
            for (int w = 3; w >= 0; w--)
            {
                var t = now.AddDays(-7 * w).Date.AddHours(19);
                var checks = new List<Check> { new Check { Id = "keys", Title = "Hallow Keys: 6 reused passwords", Penalty = 6, State = CheckState.Warn, FixAction = "x" } };
                if (w >= 1) checks.Add(new Check { Id = "listeners", Title = "A suspicious program is open to the network", Penalty = 6, State = CheckState.Bad, FixAction = "x" });
                if (w >= 2) checks.Add(new Check { Id = "updates", Title = "Windows updates are waiting", Penalty = 5, State = CheckState.Warn, FixAction = "x" });
                if (w == 0) checks.Add(new Check { Id = "cfa", Title = "Ransomware protection is off", Penalty = 3, State = CheckState.Warn, FixAction = "x" });
                var scans = new List<ScanRecord> { new ScanRecord { Kind = "quick", Result = "clean", End = t.AddDays(-2).ToString("o"), Away = w % 2 == 0 }, new ScanRecord { Kind = "download", Result = "clean", End = t.AddDays(-4).ToString("o") } };
                var r = Build(new ReportInput { Now = t, Week = Weeks.Key(t), Score = scores[3 - w], Checks = checks, Scans = scans, Threats = new List<ThreatRecord>(), Previous = prev, Changes = w == 3 ? null : w == 0 ? Changes() : new SnapDiff { Since = Weeks.Key(t.AddDays(-7)), New = { new SnapItem { Kind = "Extension", Label = "Old Tab Saver (Brave)", Id = "o" } } } });
                l.Insert(0, r); prev = r;
            }
            return l;
        }
        static Dictionary<string, object> Build(ReportInput i) { return WeeklyReport.Build(i); }
    }
}
