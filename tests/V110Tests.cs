// Hallow Guard 1.10 tests: "Recently blocked by Ransomware protection". Made-up 1123 / 1124 event XML, grouping, the trusted /
// "check before allowing" classification, the Windows Security link, the can't-read-the-log message, the quiet note's rules, and
// that Guard's source never changes a Defender setting. Never touches a Defender setting itself; the one live check only READS
// whether this account can open the event channel (and passes either way, saying which).
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HallowGuard.Tests
{
    public static class V110Tests
    {
        static Action<bool, string> Ok;
        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            Parsing(); Folders(); Classification(); Grouping(); Uri(); Unreadable(); Notes(); NeverChanges(); LiveRead();
        }

        const string Prof = @"C:\Users\Alex", Lad = @"C:\Users\Alex\AppData\Local", Win = @"C:\Windows";
        static string Xml(int id, string utc, string proc, string path, string user = @"PC\Alex")
        {
            return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}'/>"
                + "<EventID>" + id + "</EventID><Version>0</Version><Level>3</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>"
                + "<TimeCreated SystemTime='" + utc + "'/><EventRecordID>42</EventRecordID><Correlation/><Execution ProcessID='1' ThreadID='2'/>"
                + "<Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>PC</Computer><Security UserID='S-1-5-18'/></System>"
                + "<EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.1.1</Data><Data Name='Unused'></Data><Data Name='ID'></Data>"
                + "<Data Name='Detection Time'>" + utc + "</Data><Data Name='User'>" + user + "</Data><Data Name='Path'>" + path + "</Data>"
                + "<Data Name='Process Name'>" + proc + "</Data><Data Name='Security intelligence Version'>1.1.1.0</Data><Data Name='Engine Version'>1.1.1.1</Data></EventData></Event>";
        }
        const string Snip = @"C:\Program Files\WindowsApps\Microsoft.ScreenSketch_11.2609.15.0_x64__8wekyb3d8bbwe\SnippingTool\SnippingTool.exe";

        static void Parsing()
        {
            var e = CfaBlocks.Parse(Xml(1123, "2026-11-23T04:13:39.5893091Z", Snip, @"%userprofile%\OneDrive\Pictures"));
            Ok(e != null && e.Id == 1123 && !e.Audit && e.Process == Snip && e.Path == @"%userprofile%\OneDrive\Pictures" && e.User == @"PC\Alex", "1123 parsed: app, folder, user, blocked (not audit)");
            Ok(e != null && e.Time == new DateTime(2026, 11, 23, 4, 13, 39, DateTimeKind.Utc).AddTicks(5893091).ToLocalTime(), "1123: the UTC time becomes local time (" + (e == null ? "-" : e.Time.ToString("o")) + ")");
            var a = CfaBlocks.Parse(Xml(1124, "2026-11-22T10:00:00.000Z", @"C:\Games\Foo\foo.exe", @"C:\Users\Alex\Documents\My Games\Foo\save1.dat"));
            Ok(a != null && a.Id == 1124 && a.Audit, "1124 parsed as audit (would have been blocked)");
            Ok(CfaBlocks.Parse(Xml(1127, "2026-11-22T10:00:00Z", @"C:\x.exe", @"C:\y")) == null, "other event ids (1127) are ignored");
            Ok(CfaBlocks.Parse(Xml(1123, "2026-11-22T10:00:00Z", "", @"C:\y")) == null, "an event without an app is ignored");
            Ok(CfaBlocks.Parse("<not xml") == null && CfaBlocks.Parse(null) == null && CfaBlocks.Parse("") == null, "broken / empty XML gives nothing, no exception");
            var amp = CfaBlocks.Parse(Xml(1123, "2026-11-22T10:00:00Z", @"C:\Tools\Tom &amp; Jerry\tj.exe", @"%userprofile%\Desktop"));
            Ok(amp != null && amp.Process == @"C:\Tools\Tom & Jerry\tj.exe", "XML escapes in paths are decoded");
        }

        static void Folders()
        {
            Ok(CfaBlocks.Expand(@"%userprofile%\OneDrive\Pictures", Prof) == @"C:\Users\Alex\OneDrive\Pictures", "%userprofile% expands to the profile folder");
            Ok(CfaBlocks.Expand(@"%USERPROFILE%\Documents", Prof) == @"C:\Users\Alex\Documents", "%USERPROFILE% (any case) expands too");
            Ok(CfaBlocks.Expand(@"D:\Saves", Prof) == @"D:\Saves", "a plain path stays as it is");
            Ok(CfaBlocks.FolderWord(@"C:\Users\Alex\OneDrive\Pictures") == "Pictures", "folder word: OneDrive\\Pictures -> Pictures");
            Ok(CfaBlocks.FolderWord(@"C:\Users\Alex\Pictures\Screenshots") == @"Pictures\Screenshots", "folder word: Pictures\\Screenshots");
            Ok(CfaBlocks.FolderWord(@"C:\Users\Alex\Documents\My Games\Foo\save1.dat") == @"Documents\My Games", "folder word: a save file in Documents\\My Games");
            Ok(CfaBlocks.FolderWord(@"E:\Protected\Work\report.docx") == "Work", "folder word: an extra protected folder -> its own name");
            Ok(CfaBlocks.FolderWord(null) == "a protected folder" && CfaBlocks.FolderWord(@"E:\") == "a protected folder", "folder word: nothing / a drive -> \"a protected folder\"");
        }

        static void Classification()
        {
            Func<string, string, string> t = (exe, signer) => CfaBlocks.Classify(exe, signer, Lad, Win).Item1;
            Func<string, string, string> why = (exe, signer) => CfaBlocks.Classify(exe, signer, Lad, Win).Item2;
            Ok(t(Snip, "Microsoft Corporation") == "trusted" && why(Snip, "Microsoft Corporation") == "Microsoft Corporation", "Snipping Tool (signed by Microsoft): trusted publisher");
            Ok(t(@"C:\Program Files\obs-studio\bin\64bit\obs64.exe", "OBS Project, LLC") == "trusted", "OBS (signed by OBS Project): trusted");
            Ok(t(@"C:\Program Files (x86)\Steam\steam.exe", "Valve Corp.") == "trusted", "Steam (signed by Valve): trusted");
            Ok(t(@"D:\SteamLibrary\steamapps\common\Example Quest\ExampleQuest.exe", null) == "trusted" && why(@"D:\SteamLibrary\steamapps\common\Example Quest\ExampleQuest.exe", null).StartsWith("Steam game"), "an unsigned game in a Steam library: trusted (Steam game)");
            Ok(t(Lad + @"\Programs\Hallow Clips\HallowClips.exe", null) == "trusted" && why(Lad + @"\Programs\Hallow Clips\HallowClips.exe", null) == "Hallow app", "a Hallow app in its install folder (unsigned): trusted (Hallow app)");
            Ok(t(@"C:\Users\Alex\Downloads\HallowClips.exe", null) == "check", "a file merely NAMED like a Hallow app, in Downloads: check before allowing");
            Ok(t(Lad + @"\Programs\Hallow Clips\evil.exe", null) == "check", "a non-Hallow exe inside a Hallow folder: check");
            Ok(t(@"C:\Windows\explorer.exe", null) == "trusted" && why(@"C:\Windows\explorer.exe", null) == "Part of Windows", "Windows' own (catalog-signed) explorer.exe: trusted (part of Windows)");
            Ok(t(@"C:\Windows\Temp\x\setup.exe", null) == "check", "an unsigned exe in C:\\Windows\\Temp: check");
            Ok(t(@"C:\Program Files\WindowsApps\SpotifyAB.SpotifyMusic_1.310.2586.0_x64__zpdnekdrzrea0\Spotify.exe", null) == "trusted" && why(@"C:\Program Files\WindowsApps\SpotifyAB.SpotifyMusic_1.310.2586.0_x64__zpdnekdrzrea0\Spotify.exe", null) == "Microsoft Store app from SpotifyAB", "a Store app (package signature): trusted, says which package");
            Ok(why(Snip, null) == "Microsoft Corporation (Store app)", "Microsoft's own Store package: Microsoft Corporation (Store app)");
            Ok(t(@"C:\Users\Alex\Downloads\FreeFpsBooster.exe", null) == "check" && why(@"C:\Users\Alex\Downloads\FreeFpsBooster.exe", null) == "Not signed", "unsigned app in Downloads: check before allowing (Not signed)");
            Ok(t(@"C:\Users\Alex\AppData\Roaming\x\tool.exe", "Some Unknown Ltd") == "check" && why(@"C:\Users\Alex\AppData\Roaming\x\tool.exe", "Some Unknown Ltd").Contains("Some Unknown Ltd"), "signed by a publisher Guard doesn't know: check, and says who signed it");
            Ok(!CfaBlocks.KnownPublisher("") && !CfaBlocks.KnownPublisher(null) && CfaBlocks.KnownPublisher("Microsoft Windows"), "known publishers: empty / null aren't, Microsoft Windows is");
        }

        static void Grouping()
        {
            var now = new DateTime(2026, 11, 23, 12, 0, 0);
            var ev = new List<CfaBlockEvent>();
            for (int i = 0; i < 4; i++) ev.Add(new CfaBlockEvent { Id = 1123, Time = now.AddHours(-i), Process = Snip, Path = @"%userprofile%\OneDrive\Pictures" });
            ev.Add(new CfaBlockEvent { Id = 1123, Time = now.AddHours(-5), Process = Snip.ToUpperInvariant(), Path = @"%userprofile%\Pictures\Screenshots" });   // same app, other case
            ev.Add(new CfaBlockEvent { Id = 1124, Time = now.AddDays(-2), Process = @"C:\Games\Foo\foo.exe", Path = @"%userprofile%\Documents" });
            ev.Add(new CfaBlockEvent { Id = 1123, Time = now.AddDays(-20), Process = @"C:\Old\old.exe", Path = @"%userprofile%\Documents" });   // too old
            ev.Add(null);
            var g = CfaBlocks.Group(ev, now, Prof, Lad, Win, exe => exe.EndsWith("SnippingTool.exe", StringComparison.OrdinalIgnoreCase) ? "Microsoft Corporation" : null, exe => exe.EndsWith("SnippingTool.exe", StringComparison.OrdinalIgnoreCase) ? "Snipping Tool" : null);
            Ok(g.Count == 2, "grouped per app (case-insensitive), older than " + CfaBlocks.Days + " days dropped: " + g.Count + " apps");
            var s = g.FirstOrDefault(x => x.Name.Equals("SnippingTool.exe", StringComparison.OrdinalIgnoreCase));
            Ok(s != null && s.Count == 5 && s.Last == now && s.Display == "Snipping Tool" && s.Trust == "trusted", "Snipping Tool: 5 blocks, last time, friendly name, trusted");
            Ok(s != null && s.Folders.Count == 2 && s.Folders[0] == @"C:\Users\Alex\OneDrive\Pictures" && s.Folders[1] == @"C:\Users\Alex\Pictures\Screenshots", "its folders expanded, newest first, no repeats");
            var f = g.FirstOrDefault(x => x.Name == "foo.exe");
            Ok(f != null && f.AuditOnly && f.Trust == "check" && f.Display == "foo.exe", "audit-only app flagged as audit; unsigned -> check; no description -> file name");
            Ok(g[0] == s, "newest first");
            Ok(CfaBlocks.Headline(g) == "Ransomware protection blocked 2 apps recently" && CfaBlocks.Headline(g.Take(1).ToList()) == "Ransomware protection blocked 1 app recently", "headline: \"blocked N apps recently\" / \"1 app\"");
            Ok(CfaBlocks.Headline(new List<BlockedApp> { f }) == "Ransomware protection would have blocked 1 app recently", "headline in audit mode: \"would have blocked\"");
            Ok(CfaBlocks.CountLine(s, now) == "Blocked 5 times, last today 12:00" && CfaBlocks.CountLine(f, now).StartsWith("Would have been blocked once, last "), "count line: times and when (" + CfaBlocks.CountLine(f, now) + ")");
            Ok(CfaBlocks.Group(null, now, Prof, Lad, Win, null, null).Count == 0, "no events: no apps");
            var fake = CfaBlocks.Group(FakeCfaBlocks.Sample(now).Events, now, FakeCfaBlocks.Profile, FakeCfaBlocks.LocalAppData, FakeCfaBlocks.WinDir, FakeCfaBlocks.Signer, FakeCfaBlocks.Display);
            Ok(fake.Count == 5 && fake.Count(x => x.Trust == "check") == 1 && fake.Single(x => x.Trust == "check").Name == "FreeFpsBooster.exe", "--snap data: 5 apps, only the unsigned download flagged");
        }

        static void Uri()
        {
            Ok(CfaBlocks.AllowPage == "windowsdefender://allowappthroughfolder/", "the button opens windowsdefender://allowappthroughfolder/ (Ransomware protection > Allow an app through Controlled folder access)");
            Ok(CfaBlocks.AllowPage.StartsWith("windowsdefender:"), "RunFix opens it (windowsdefender: links are the only Windows Security pages it starts)");
            Ok(CfaBlocks.Steps == "Yes on the Windows prompt > Add an allowed app > Recently blocked apps > the + next to the app", "the one line of steps");
            var src = Src("PagesCfa.cs") + Src("Pages12.cs");
            Ok(src.Contains("c.RunFix(CfaBlocks.AllowPage)") && src.Contains("\"Allow in Windows Security\""), "\"Allow in Windows Security\" and \"Allow an app\" go to that page");
        }

        static void Unreadable()
        {
            var denied = new CfaBlockRead { Problem = "denied" };
            var t = CfaBlocks.ProblemText(denied);
            Ok(t != null && t.Contains("doesn't let this account read") && t.Contains("won't ask for admin") && t.Contains("Recently blocked apps") && t.Contains("Yes on the Windows prompt"), "log unreadable: says why, no admin from Guard, and where Windows Security keeps the list");
            Ok(CfaBlocks.ProblemText(new CfaBlockRead { Problem = "missing" }).Contains("isn't on this PC"), "log missing (another antivirus): explained");
            Ok(CfaBlocks.ProblemText(new CfaBlockRead { Problem = "error: The RPC server is unavailable" }).Contains("(The RPC server is unavailable)"), "other errors: the reason in brackets");
            Ok(CfaBlocks.ProblemText(new CfaBlockRead { Readable = true }) == null, "readable: no problem text");
            var r = new FakeCfaBlocks(); FakeCfaBlocks.Unreadable = true;
            try { var x = r.Read(DateTime.Now.AddDays(-14)); Ok(!x.Readable && x.Problem == "denied" && x.Events.Count == 0, "the made-up unreadable log (for --snap): denied, no events"); }
            finally { FakeCfaBlocks.Unreadable = false; }
        }

        static void Notes()
        {
            var now = new DateTime(2026, 11, 23, 20, 0, 0);
            Func<double, string, string, int, CfaBlockEvent> E = (minsAgo, exe, path, id) => new CfaBlockEvent { Id = id, Time = now.AddMinutes(-minsAgo), Process = exe, Path = path };
            var ev = new List<CfaBlockEvent> { E(3, Snip, @"%userprofile%\OneDrive\Pictures", 1123), E(60, @"C:\Games\Foo\foo.exe", @"%userprofile%\Documents", 1123) };
            var seen = now.AddMinutes(-30);
            var d = CfaBlocks.Decide(true, null, ev, seen, null, now, Prof);
            Ok(d.Text == "SnippingTool.exe was blocked from saving to Pictures. Allow it?" && d.SeenUpTo == now.AddMinutes(-3), "note: the exact text, only blocks newer than the last one seen");
            d = CfaBlocks.Decide(false, null, ev, seen, null, now, Prof);
            Ok(d.Text == null && !d.Held && d.SeenUpTo == now.AddMinutes(-3), "notes off (the default): no note, and the blocks count as seen");
            Ok(!new GuardSettings().CfaNotes, "the setting is off by default");
            d = CfaBlocks.Decide(true, "a game is running", ev, seen, null, now, Prof);
            Ok(d.Text == null && d.Held && d.SeenUpTo == seen, "held while a game runs - not marked seen, so it goes out afterwards");
            d = CfaBlocks.Decide(true, "a full-screen app is open", ev, seen, null, now, Prof);
            Ok(d.Text == null && d.Held, "held while a full-screen app is open");
            d = CfaBlocks.Decide(true, null, ev, seen, now.AddMinutes(-4), now, Prof);
            Ok(d.Text == null && d.Held, "at most one note every " + CfaBlocks.NoteGapMinutes + " minutes");
            d = CfaBlocks.Decide(true, null, ev, null, null, now, Prof);
            Ok(d.Text == null && d.SeenUpTo == now.AddMinutes(-3), "first look: older blocks aren't noted");
            d = CfaBlocks.Decide(true, null, new List<CfaBlockEvent> { E(2, @"C:\Games\Foo\foo.exe", @"%userprofile%\Documents", 1124) }, seen, null, now, Prof);
            Ok(d.Text == null, "audit-only events never make a note");
            var two = new List<CfaBlockEvent> { E(1, Snip, @"%userprofile%\Pictures\Screenshots", 1123), E(2, @"C:\a\b.exe", @"%userprofile%\Documents", 1123), E(3, @"C:\a\c.exe", @"%userprofile%\Documents", 1123) };
            d = CfaBlocks.Decide(true, null, two, seen, null, now, Prof);
            Ok(d.Text == @"SnippingTool.exe was blocked from saving to Pictures\Screenshots (and 2 other apps). Allow it?", "several apps: one note (" + d.Text + ")");
            d = CfaBlocks.Decide(true, null, ev, now, null, now, Prof);
            Ok(d.Text == null && !d.Held, "nothing new: nothing");
            var src = Src("App.cs");
            Ok(src.Contains("Notify(\"Ransomware protection blocked an app\", d.Text") && src.Contains("\"overview\");") && src.Contains("BalloonTipClicked"), "the note opens Guard at the card (overview) when clicked");
            Ok(src.Contains("var busy = busySrc.Busy();") && src.Contains("CfaBlocks.Decide(S.CfaNotes, busy"), "the note asks the same game / full-screen check as the other balloons");
        }

        // Guard's source: no Defender setting is ever changed (no Set-/Add-MpPreference, no MSFT_MpPreference method calls, no registry
        // writes under Defender, no "runas" for this feature)
        static void NeverChanges()
        {
            var dir = SrcDir(); if (dir == null) { Ok(false, "source folder not found"); return; }
            var all = string.Join("\n", Directory.GetFiles(dir, "*.cs").Select(File.ReadAllText));
            // the only mentions are in the Hardening page's "how to do it yourself" steps (text that ends "Hallow Guard never changes this for you")
            var writes = all.Split('\n').Where(l => System.Text.RegularExpressions.Regex.IsMatch(l, "(Set|Add|Remove)-MpPreference")).ToList();
            Ok(writes.All(l => l.Contains("never changes this for you") && !l.Contains("Process.Start") && !l.Contains("ArgumentList") && !l.Contains("Arguments")), "Set- / Add- / Remove-MpPreference only appear in instructions for the user (" + writes.Count + " lines), never in anything Guard runs");
            Ok(!System.Text.RegularExpressions.Regex.IsMatch(Src("CfaBlocks.cs") + Src("PagesCfa.cs"), "(Set|Add|Remove)-MpPreference"), "the new feature doesn't mention them at all");
            Ok(!System.Text.RegularExpressions.Regex.IsMatch(all, "InvokeMethod\\(\\s*\"(Set|Add|Remove)\""), "no MSFT_MpPreference Set / Add / Remove method calls");
            Ok(!System.Text.RegularExpressions.Regex.IsMatch(all, "CreateSubKey\\([^)]*Windows Defender"), "no registry writes under Windows Defender");
            var cfa = Src("CfaBlocks.cs") + Src("PagesCfa.cs");
            Ok(!cfa.Contains("runas") && !cfa.Contains("Verb =") && !cfa.Contains("Registry.") && !cfa.Contains("ManagementObject"), "the new feature has no elevation, registry or WMI calls - it only reads the event log");
            Ok(cfa.Contains("new EventLogQuery(") && cfa.Contains("EventLogReader"), "it reads with EventLogQuery / EventLogReader (read-only)");
        }

        // read-only: can this account open Defender's operational log? (passes either way - says which)
        static void LiveRead()
        {
            var r = new WindowsCfaBlocks().Read(DateTime.Now.AddDays(-1));
            Ok(r.Readable || r.Problem != null, "live (read-only): this account " + (r.Readable ? "CAN read " + CfaBlocks.Channel + " (" + r.Events.Count + " block events in 24 h)" : "can't read the log: " + r.Problem));
        }

        static string SrcDir()
        {
            var d = AppDomain.CurrentDomain.BaseDirectory;
            for (int i = 0; i < 4 && d != null; i++) { var s = Path.Combine(d, "src"); if (File.Exists(Path.Combine(s, "CfaBlocks.cs"))) return s; d = Path.GetDirectoryName(d.TrimEnd('\\')); }
            return null;
        }
        static string Src(string f) { var d = SrcDir(); return d == null ? "" : File.ReadAllText(Path.Combine(d, f)); }
    }
}
