// Hallow Guard v1.10 - "Recently blocked by Ransomware protection". Read-only: Guard reads Microsoft Defender's own event log
// (Microsoft-Windows-Windows Defender/Operational: 1123 = Controlled folder access blocked an app, 1124 = audit mode, it would have),
// groups the blocks per app, checks each app's signature and says whether it's from a publisher you'd expect or worth a look first.
// Allowing an app stays yours: the button opens Windows Security at "Allow an app through Controlled folder access"
// (windowsdefender://allowappthroughfolder/), where Windows asks for admin itself. Guard never changes Defender's settings, never
// adds allowed apps and never asks for admin for this.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Xml;

namespace HallowGuard
{
    public class CfaBlockEvent
    {
        public int Id;                 // 1123 blocked | 1124 audited (would have been blocked)
        public DateTime Time;          // local time
        public string Process;         // the app's full path
        public string Path;            // the protected folder or file it tried to change (as Defender wrote it, %userprofile% and all)
        public string User;
        public bool Audit { get { return Id == 1124; } }
    }

    public class BlockedApp
    {
        public string Exe, Name, Display;        // full path, file name, friendly name (the file's description when there is one)
        public string Signer;                    // embedded signature's publisher, or "Microsoft Windows" for Windows' own catalog-signed files
        public string Trust;                     // "trusted" | "check"
        public string Why;                       // one short reason: "Microsoft Corporation", "Hallow app", "Steam game", "Not signed"...
        public int Count, Audits;
        public DateTime Last;
        public List<string> Folders = new List<string>();   // expanded, newest first
        public bool AuditOnly { get { return Audits == Count; } }
    }

    public class CfaBlockRead
    {
        public bool Readable;           // the log could be read
        public string Problem;          // "denied" | "missing" | "error: ..." when it couldn't
        public List<CfaBlockEvent> Events = new List<CfaBlockEvent>();
        public DateTime? When;
    }

    public interface ICfaBlockSource { CfaBlockRead Read(DateTime since); }

    public static class CfaBlocks
    {
        public const string Channel = "Microsoft-Windows-Windows Defender/Operational";
        public const string AllowPage = "windowsdefender://allowappthroughfolder/";   // Ransomware protection > Allow an app through Controlled folder access
        public const string Steps = "Yes on the Windows prompt > Add an allowed app > Recently blocked apps > the + next to the app";
        public const int Days = 14;

        // ---- parsing one event's XML (EventRecord.ToXml()); null when it isn't a 1123 / 1124 or has no app
        public static CfaBlockEvent Parse(string xml)
        {
            if (string.IsNullOrEmpty(xml)) return null;
            try
            {
                var doc = new XmlDocument(); doc.LoadXml(xml);
                var ns = new XmlNamespaceManager(doc.NameTable); ns.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event");
                var idn = doc.SelectSingleNode("/e:Event/e:System/e:EventID", ns); int id;
                if (idn == null || !int.TryParse(idn.InnerText.Trim(), out id) || (id != 1123 && id != 1124)) return null;
                var ev = new CfaBlockEvent { Id = id };
                var tc = doc.SelectSingleNode("/e:Event/e:System/e:TimeCreated/@SystemTime", ns); DateTime t;
                if (tc != null && DateTime.TryParse(tc.Value, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out t)) ev.Time = DateTime.SpecifyKind(t, DateTimeKind.Utc).ToLocalTime();
                foreach (XmlNode d in doc.SelectNodes("/e:Event/e:EventData/e:Data", ns))
                {
                    var name = d.Attributes == null || d.Attributes["Name"] == null ? "" : d.Attributes["Name"].Value;
                    var v = d.InnerText.Trim();
                    if (name == "Process Name") ev.Process = v;
                    else if (name == "Path") ev.Path = v;
                    else if (name == "User") ev.User = v;
                }
                if (string.IsNullOrEmpty(ev.Process)) return null;
                return ev;
            }
            catch { return null; }
        }

        // %userprofile% (and the like) in Defender's paths -> real folders. profile: the user's folder (tests pass a made-up one)
        public static string Expand(string path, string profile)
        {
            if (string.IsNullOrEmpty(path)) return path;
            var p = path;
            if (!string.IsNullOrEmpty(profile)) p = System.Text.RegularExpressions.Regex.Replace(p, "%userprofile%", profile.TrimEnd('\\').Replace("$", "$$"), System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            try { p = Environment.ExpandEnvironmentVariables(p); } catch { }
            return p;
        }

        static readonly string[] KnownNames = { "Documents", "Pictures", "Desktop", "Videos", "Music", "Favorites", "Saved Games", "Downloads", "Screenshots", "My Games" };
        // a short name for where it tried to write: "Pictures", "Documents"... (the deepest known folder in the path), else the folder's own name
        public static string FolderWord(string path)
        {
            if (string.IsNullOrEmpty(path)) return "a protected folder";
            var parts = path.TrimEnd('\\').Split('\\');
            for (int i = parts.Length - 1; i >= 0; i--)
                foreach (var k in KnownNames) if (parts[i].Equals(k, StringComparison.OrdinalIgnoreCase))
                    return k == "Screenshots" || k == "My Games" ? (i > 0 && KnownNames.Contains(parts[i - 1], StringComparer.OrdinalIgnoreCase) ? parts[i - 1] + "\\" + k : k) : k;
            var last = parts[parts.Length - 1];
            if (last.Contains(".") && parts.Length > 1) last = parts[parts.Length - 2];   // a file: its folder
            return last.Length == 0 || last.EndsWith(":") ? "a protected folder" : last;
        }

        // ---- trusted or "check before allowing"
        static readonly string[] Publishers = {
            "Microsoft Corporation", "Microsoft Windows", "Valve", "OBS Project", "Spotify AB", "NVIDIA Corporation", "Advanced Micro Devices", "Discord Inc",
            "Google LLC", "Mozilla Corporation", "Epic Games", "Electronic Arts", "Ubisoft", "Riot Games", "Blizzard Entertainment", "Adobe Inc", "Logitech",
            "Corsair", "Razer", "Elgato", "Intel Corporation", "Dropbox", "Zoom Video Communications", "Brave Software", "Opera Norway", "VideoLAN", "Apple Inc", "Medal B.V.", "Overwolf" };
        public static bool KnownPublisher(string signer)
        {
            if (string.IsNullOrEmpty(signer)) return false;
            var s = signer.Trim();
            return Publishers.Any(p => s.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        }
        public static bool IsHallowApp(string exe, string localAppData)
        {
            if (string.IsNullOrEmpty(exe) || string.IsNullOrEmpty(localAppData)) return false;
            var dir = System.IO.Path.Combine(localAppData, "Programs");
            var name = System.IO.Path.GetFileName(exe);
            return exe.StartsWith(dir.TrimEnd('\\') + "\\Hallow ", StringComparison.OrdinalIgnoreCase) && name.StartsWith("Hallow", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        }
        public static bool IsSteamGame(string exe)
        {
            return !string.IsNullOrEmpty(exe) && exe.IndexOf("\\steamapps\\common\\", StringComparison.OrdinalIgnoreCase) > 0;
        }
        // an app installed from the Microsoft Store (Program Files\WindowsApps: Windows checks the package's signature when it installs)
        public static bool IsStoreApp(string exe) { return !string.IsNullOrEmpty(exe) && exe.IndexOf(":\\Program Files\\WindowsApps\\", StringComparison.OrdinalIgnoreCase) > 0; }
        public static string StorePublisher(string exe)
        {
            try
            {
                var i = exe.IndexOf("\\WindowsApps\\", StringComparison.OrdinalIgnoreCase) + 13; var pkg = exe.Substring(i).Split('\\')[0];
                if (pkg.EndsWith("_8wekyb3d8bbwe", StringComparison.OrdinalIgnoreCase)) return "Microsoft Corporation (Store app)";
                var dot = pkg.IndexOf('.'); return "Microsoft Store app" + (dot > 0 ? " from " + pkg.Substring(0, dot) : "");
            }
            catch { return "Microsoft Store app"; }
        }
        public static bool IsWindowsFile(string exe, string windir)
        {
            if (string.IsNullOrEmpty(exe) || string.IsNullOrEmpty(windir)) return false;
            return exe.StartsWith(windir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase) && exe.IndexOf("\\Temp\\", StringComparison.OrdinalIgnoreCase) < 0;
        }
        // trust, reason. signer: the embedded signature's publisher (null = unsigned / invalid)
        public static Tuple<string, string> Classify(string exe, string signer, string localAppData, string windir)
        {
            if (IsHallowApp(exe, localAppData)) return Tuple.Create("trusted", "Hallow app");
            if (KnownPublisher(signer)) return Tuple.Create("trusted", signer);
            if (signer == null && IsWindowsFile(exe, windir)) return Tuple.Create("trusted", "Part of Windows");
            if (signer == null && IsStoreApp(exe)) return Tuple.Create("trusted", StorePublisher(exe));
            if (IsSteamGame(exe)) return Tuple.Create("trusted", "Steam game" + (signer != null ? " - " + signer : ""));
            if (signer != null) return Tuple.Create("check", "Signed by " + signer + " - not a publisher Guard knows");
            return Tuple.Create("check", "Not signed");
        }

        // ---- per app, newest first. signerOf / displayOf: tests pass made-up ones; the real ones read the file
        public static List<BlockedApp> Group(IEnumerable<CfaBlockEvent> events, DateTime now, string profile, string localAppData, string windir, Func<string, string> signerOf, Func<string, string> displayOf)
        {
            var since = now.AddDays(-Days);
            var r = new List<BlockedApp>();
            foreach (var g in (events ?? new CfaBlockEvent[0]).Where(e => e != null && !string.IsNullOrEmpty(e.Process) && e.Time >= since && e.Time <= now.AddMinutes(5)).GroupBy(e => e.Process, StringComparer.OrdinalIgnoreCase))
            {
                var l = g.OrderByDescending(e => e.Time).ToList();
                var exe = l[0].Process;
                var a = new BlockedApp { Exe = exe, Name = System.IO.Path.GetFileName(exe), Count = l.Count, Audits = l.Count(e => e.Audit), Last = l[0].Time };
                foreach (var e in l) { var f = Expand(e.Path, profile); if (!string.IsNullOrEmpty(f) && !a.Folders.Contains(f, StringComparer.OrdinalIgnoreCase)) a.Folders.Add(f); }
                string signer = null; try { signer = signerOf == null ? null : signerOf(exe); } catch { }
                a.Signer = signer;
                var c = Classify(exe, signer, localAppData, windir); a.Trust = c.Item1; a.Why = c.Item2;
                if (a.Trust == "trusted" && signer == null && IsWindowsFile(exe, windir)) a.Signer = "Microsoft Windows";
                string disp = null; try { disp = displayOf == null ? null : displayOf(exe); } catch { }
                a.Display = string.IsNullOrWhiteSpace(disp) ? a.Name : disp.Trim();
                r.Add(a);
            }
            return r.OrderByDescending(x => x.Last).ToList();
        }

        public static string Headline(List<BlockedApp> apps)
        {
            if (apps == null || apps.Count == 0) return "Ransomware protection hasn't blocked anything lately";
            bool audit = apps.All(a => a.AuditOnly);
            return "Ransomware protection " + (audit ? "would have blocked " : "blocked ") + apps.Count + (apps.Count == 1 ? " app" : " apps") + " recently";
        }
        public static string CountLine(BlockedApp a, DateTime now)
        {
            var times = a.Count == 1 ? "once" : a.Count == 2 ? "twice" : a.Count + " times";
            var when = a.Last.Date == now.Date ? "today " + a.Last.ToString("HH:mm") : a.Last.Date == now.Date.AddDays(-1) ? "yesterday " + a.Last.ToString("HH:mm") : a.Last.ToString("d MMM, HH:mm");
            return (a.AuditOnly ? "Would have been blocked " : "Blocked ") + times + ", last " + when;
        }

        // the explanation when the log can't be read (a standard account on some PCs, or Defender isn't the antivirus)
        public static string ProblemText(CfaBlockRead r)
        {
            if (r == null) return "Checking Defender's log...";
            if (r.Readable) return null;
            if (r.Problem == "denied")
                return "Windows doesn't let this account read Microsoft Defender's log, so Hallow Guard can't list what Ransomware protection blocked. Guard won't ask for admin just to read it. Windows Security keeps its own list: open it with the button, click Yes on the Windows prompt, then Add an allowed app > Recently blocked apps.";
            if (r.Problem == "missing")
                return "Microsoft Defender's log isn't on this PC (another antivirus may be in charge), so there's nothing to list here. Windows Security shows what Ransomware protection blocked, if it's on.";
            return "Couldn't read Microsoft Defender's log just now" + (r.Problem != null && r.Problem.StartsWith("error: ") ? " (" + r.Problem.Substring(7) + ")" : "") + ". Windows Security keeps its own list under Ransomware protection > Allow an app > Recently blocked apps.";
        }

        // ---- the optional quiet note (off by default). Held while a game or full-screen app runs; at most one every 10 minutes;
        // never for audit-only events. seenUpTo: the newest block already noted (or skipped). Returns the text, or null.
        public const int NoteGapMinutes = 10;
        public static string NoteText(List<CfaBlockEvent> fresh, string profile)
        {
            if (fresh == null || fresh.Count == 0) return null;
            var newest = fresh.OrderByDescending(e => e.Time).First();
            int others = fresh.Select(e => e.Process).Distinct(StringComparer.OrdinalIgnoreCase).Count() - 1;
            var f = FolderWord(Expand(newest.Path, profile));
            return System.IO.Path.GetFileName(newest.Process) + " was blocked from saving to " + f + (others > 0 ? " (and " + others + " other " + (others == 1 ? "app" : "apps") + ")" : "") + ". Allow it?";
        }
        public class NoteDecision { public string Text; public bool Held; public DateTime? SeenUpTo; public string Why; }
        public static NoteDecision Decide(bool on, string busy, IEnumerable<CfaBlockEvent> events, DateTime? seenUpTo, DateTime? lastNote, DateTime now, string profile)
        {
            var all = (events ?? new CfaBlockEvent[0]).Where(e => e != null && !e.Audit && !string.IsNullOrEmpty(e.Process)).ToList();
            var newest = all.Count == 0 ? seenUpTo : all.Max(e => e.Time);
            if (seenUpTo == null) return new NoteDecision { SeenUpTo = newest ?? now, Why = "first look: older blocks aren't noted" };
            var fresh = all.Where(e => e.Time > seenUpTo.Value).ToList();
            if (!on) return new NoteDecision { SeenUpTo = newest, Why = "notes are off" };
            if (fresh.Count == 0) return new NoteDecision { SeenUpTo = seenUpTo, Why = "nothing new" };
            if (busy != null) return new NoteDecision { Held = true, SeenUpTo = seenUpTo, Why = "held: " + busy };
            if (lastNote != null && (now - lastNote.Value).TotalMinutes < NoteGapMinutes) return new NoteDecision { Held = true, SeenUpTo = seenUpTo, Why = "held: a note went out less than " + NoteGapMinutes + " minutes ago" };
            return new NoteDecision { Text = NoteText(fresh, profile), SeenUpTo = newest, Why = "note" };
        }
    }

    // the real PC: Defender's operational log, read-only (no admin needed when Windows lets interactive users read it - the default)
    public class WindowsCfaBlocks : ICfaBlockSource
    {
        public CfaBlockRead Read(DateTime since)
        {
            var r = new CfaBlockRead { When = DateTime.Now };
            try
            {
                long ms = Math.Max(60000, (long)(DateTime.Now - since).TotalMilliseconds);
                var q = new EventLogQuery(CfaBlocks.Channel, PathType.LogName, "*[System[(EventID=1123 or EventID=1124) and TimeCreated[timediff(@SystemTime) <= " + ms + "]]]") { ReverseDirection = true };
                using (var rd = new EventLogReader(q))
                {
                    for (int i = 0; i < 1000; i++)
                    {
                        using (var e = rd.ReadEvent())
                        {
                            if (e == null) break;
                            var ev = CfaBlocks.Parse(e.ToXml()); if (ev != null) r.Events.Add(ev);
                        }
                    }
                }
                r.Readable = true;
            }
            catch (UnauthorizedAccessException) { r.Problem = "denied"; }
            catch (EventLogNotFoundException) { r.Problem = "missing"; }
            catch (EventLogException e) { r.Problem = e.Message.IndexOf("denied", StringComparison.OrdinalIgnoreCase) >= 0 ? "denied" : "error: " + e.Message.Trim(); }
            catch (Exception e) { r.Problem = "error: " + e.Message.Trim(); }
            return r;
        }
        public static string Display(string exe)
        {
            try { if (!File.Exists(exe)) return null; var v = FileVersionInfo.GetVersionInfo(exe); var d = v.FileDescription; return string.IsNullOrWhiteSpace(d) || d.Trim().Length > 60 ? null : d.Trim(); }
            catch { return null; }
        }
    }

    // made-up blocks for --snap pictures and the test copy (never this PC's real apps)
    public class FakeCfaBlocks : ICfaBlockSource
    {
        public static bool Unreadable;   // --snap: the "can't read the log" picture
        public CfaBlockRead Read(DateTime since) { return Unreadable ? new CfaBlockRead { Problem = "denied", When = DateTime.Now } : Sample(DateTime.Now); }
        public static CfaBlockRead Sample(DateTime now)
        {
            var r = new CfaBlockRead { Readable = true, When = now };
            Action<int, double, string, string> add = (id, minsAgo, exe, path) => r.Events.Add(new CfaBlockEvent { Id = id, Time = now.AddMinutes(-minsAgo), Process = exe, Path = path, User = @"PC\Alex" });
            const string snip = @"C:\Program Files\WindowsApps\Microsoft.ScreenSketch_11.2609.15.0_x64__8wekyb3d8bbwe\SnippingTool\SnippingTool.exe";
            for (int i = 0; i < 6; i++) add(1123, 12 + i * 95, snip, @"%userprofile%\Pictures\Screenshots");
            add(1123, 60 * 26, @"C:\Program Files\obs-studio\bin\64bit\obs64.exe", @"%userprofile%\Videos");
            add(1123, 60 * 27, @"C:\Program Files\obs-studio\bin\64bit\obs64.exe", @"%userprofile%\Videos");
            add(1123, 60 * 50, @"D:\SteamLibrary\steamapps\common\Example Quest\ExampleQuest.exe", @"%userprofile%\Documents\My Games\Example Quest");
            add(1123, 60 * 75, @"C:\Users\Alex\Downloads\FreeFpsBooster.exe", @"%userprofile%\Documents");
            add(1124, 60 * 80, @"C:\Users\Alex\AppData\Local\Programs\Hallow Clips\HallowClips.exe", @"%userprofile%\Videos\Hallow Clips");
            return r;
        }
        public static string Signer(string exe)
        {
            var n = System.IO.Path.GetFileName(exe).ToLowerInvariant();
            return n == "snippingtool.exe" ? "Microsoft Corporation" : n == "obs64.exe" ? "OBS Project, LLC" : null;
        }
        public static string Display(string exe)
        {
            var n = System.IO.Path.GetFileName(exe).ToLowerInvariant();
            return n == "snippingtool.exe" ? "Snipping Tool" : n == "obs64.exe" ? "OBS Studio" : n == "examplequest.exe" ? "Example Quest" : n == "hallowclips.exe" ? "Hallow Clips" : null;
        }
        public const string Profile = @"C:\Users\Alex", LocalAppData = @"C:\Users\Alex\AppData\Local", WinDir = @"C:\Windows";
    }
}
