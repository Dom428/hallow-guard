// Hallow Guard v1.3 pages: Reports (the weekly safety reports), "What changed since last week" on the Leftovers page and the
// "Run a quick scan when I'm away" card in Settings.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace HallowGuard
{
    public partial class MainWindow
    {
        static List<Dictionary<string, object>> Items(Dictionary<string, object> d, string k)
        {
            var r = new List<Dictionary<string, object>>(); var v = J.Get(d, k) as System.Collections.IEnumerable;
            if (v != null && !(v is string)) foreach (var o in v) if (o is Dictionary<string, object>) r.Add((Dictionary<string, object>)o);
            return r;
        }

        // ---------------- Leftovers: what changed since last week
        FrameworkElement ChangesCard()
        {
            var s = new StackPanel();
            var d = c.Changes;
            s.Children.Add(IconRow("calendar-week", Ui.Hi, d == null ? "What changed since last week" : "What changed since " + Weeks.Nice(d.Since)));
            if (d == null)
            {
                s.Children.Add(Ui.Muted("This is the first look Hallow Guard has kept. From next week, new and removed startup items, tasks, services, extensions and programs open to the network show here.", 12, 0));
                return Card(s, 12);
            }
            if (d.New.Count == 0 && d.Removed.Count == 0) { s.Children.Add(Ui.T("Nothing new and nothing removed.", 12.5, false, Ui.Green)); return Card(s, 12); }
            var chips = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 8) };
            chips.Children.Add(Chip(d.New.Count + " new", Ui.Accent));
            if (d.NewSuspicious > 0) chips.Children.Add(Chip(d.NewSuspicious + " new suspicious", Ui.Red));
            chips.Children.Add(Chip(d.Removed.Count + " removed", Ui.R("Muted")));
            s.Children.Add(chips);
            foreach (var x in d.New.Take(12))
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
                var ic = Icons.Make("circle-plus", 13, x.Suspicious ? Ui.Red : Ui.Accent); ic.Margin = new Thickness(0, 0, 8, 0); ic.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(ic, Dock.Left); row.Children.Add(ic);
                if (x.Suspicious) { var sc = Chip("Suspicious", Ui.Red); DockPanel.SetDock(sc, Dock.Right); row.Children.Add(sc); }
                row.Children.Add(OneLine(Ui.T(x.Label + "   " + Snapshots.KindWord(x.Kind, 1), 12.5, x.Suspicious)));
                s.Children.Add(row);
            }
            foreach (var x in d.Removed.Take(8))
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
                var ic = Icons.Make("circle-minus", 13, Ui.R("Muted")); ic.Margin = new Thickness(0, 0, 8, 0); ic.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(ic, Dock.Left); row.Children.Add(ic);
                row.Children.Add(OneLine(Ui.T(x.Label + "   " + Snapshots.KindWord(x.Kind, 1) + " - gone", 12.5, false, Ui.R("Muted"))));
                s.Children.Add(row);
            }
            int more = Math.Max(0, d.New.Count - 12) + Math.Max(0, d.Removed.Count - 8);
            if (more > 0) s.Children.Add(Ui.Muted("and " + more + " more.", 11.5, 0));
            s.Children.Add(Ui.Muted("New items are marked below. Hallow Guard keeps a small list (short names and scrambled IDs, never file contents) once a week to compare with.", 11.5, 0));
            return Card(s, 12);
        }

        // ---------------- Settings: the quick scan while you're away, and the weekly report's balloon
        FrameworkElement AwayCard()
        {
            var s = new StackPanel();
            s.Children.Add(IconRow("moon", Ui.Hi, "Scans and reports"));
            s.Children.Add(Ui.Switch("Run a quick scan when I'm away", c.S.AwayScan, v => c.SetAway(v, null)));
            var every = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(30, 2, 0, 6) };
            var how = Ui.Muted("How often:", 12, 0); how.VerticalAlignment = VerticalAlignment.Center; how.Margin = new Thickness(0, 0, 10, 0); every.Children.Add(how);
            foreach (var opt in new[] { "daily", "weekly" })
            {
                var o = opt; var b = Ui.Btn(o == "daily" ? "Once a day" : "Once a week", () => { c.SetAway(c.S.AwayScan, o); Show("settings"); }, c.S.AwayEvery == o);
                b.IsEnabled = c.S.AwayScan; every.Children.Add(b);
            }
            s.Children.Add(every);
            s.Children.Add(Ui.Muted("Off by default. When you've been away from the mouse and keyboard for 10 minutes, no game or full-screen app is running, the PC is plugged in and there's been no scan for a day (or a week), Hallow Guard asks Microsoft Defender for a quick scan at low priority. It stops as soon as you come back or a game starts, and tries again later. You only hear from it if something is found.", 11.5, 6));
            if (c.S.AwayScan)
            {
                var last = c.LastAwayScan();
                s.Children.Add(Ui.Muted("Right now: " + (c.AwayStatus == null ? "waiting until you're away" : c.AwayStatus == "scanning" ? "scanning" : "waiting - " + c.AwayStatus) + ".  Last scan while you were away: " + (last == null ? "none yet" : Score.Ago(last, DateTime.Now)) + ".", 11.5, 6));
                if (!c.StartsWithWindows()) s.Children.Add(Ui.T("Hallow Guard has to be running (in the tray) for this - and Start with Windows is off, so it only happens after you've opened Hallow Guard. Turn on Start with Windows above if you want it every day.", 11.5, false, Ui.Amber, 6));
            }
            s.Children.Add(Ui.Switch("Tell me when the weekly safety report is ready (one balloon from Hallow Hub's icon, only when Hub is running and Windows notifications are on)", c.S.ReportNotify, v => { c.S.ReportNotify = v; c.S.Save(); }));
            return Card(s);
        }

        // ---------------- Reports
        FrameworkElement ReportsPage()
        {
            var sp = Page("Reports", "Once a week, while Hallow Guard is running, it writes a short safety report: your score then and now, what got fixed, new issues, scans, threats and what changed. Reports stay on this PC.");
            var thisWeek = Weeks.Key(c.Clock.Now);
            var top = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            if (c.Reports.Count == 0 || J.Str(c.Reports[0], "week") != thisWeek)
            {
                var mk = Ui.Btn(c.Hunting ? "Looking at leftovers first..." : "Make this week's report now", () => { c.MaybeReport(true); Say("Making this week's report - it takes a moment (it looks at your leftovers first)."); }, true);
                mk.IsEnabled = !c.Hunting && c.Checks != null; top.Children.Add(mk);
            }
            top.Children.Add(Ui.Btn("Open the reports folder", () =>
            {
                if (GuardSettings.TestDir != null || Snap.On) return;
                try { var d = WeeklyReport.Dir(GuardSettings.Dir); Directory.CreateDirectory(d); Process.Start("explorer.exe", "\"" + d + "\""); } catch { }
            }));
            sp.Children.Add(top);
            if (c.Reports.Count == 0)
            {
                sp.Children.Add(Card(Ui.Muted("No report yet. The first one is written this week while Hallow Guard runs (it needs to be running in the tray - Start with Windows is in Settings).", 12.5, 0)));
                return sp;
            }
            bool first = true;
            foreach (var r in c.Reports.Take(12)) { sp.Children.Add(ReportCard(r, first)); first = false; }
            if (c.Reports.Count > 12) sp.Children.Add(Ui.Muted((c.Reports.Count - 12) + " older reports are in the reports folder.", 11.5, 0));
            return sp;
        }
        FrameworkElement ReportCard(Dictionary<string, object> r, bool full)
        {
            var s = new StackPanel();
            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            var score = J.Int(r, "score"); var delta = WeeklyReport.Delta(r);
            var big = new TextBlock { Text = score == null ? "-" : score.ToString(), FontSize = 30, FontWeight = FontWeights.Bold, Foreground = score == null ? Ui.R("Muted") : ScoreBrush(score.Value), Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center };
            if (Look.IsHud) { big.FontFamily = Hud.Head; big.FontWeight = FontWeights.SemiBold; }
            DockPanel.SetDock(big, Dock.Left); head.Children.Add(big);
            if (delta != null)
            {
                var dn = Convert.ToInt32(J.Get(r, "delta"));
                var dc = Chip(delta + " since last week", dn > 0 ? Ui.Green : dn < 0 ? Ui.Red : Ui.R("Line")); DockPanel.SetDock(dc, Dock.Right); head.Children.Add(dc);
            }
            var tt = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            var created = Iso(J.Str(r, "created"));
            var wk = J.Str(r, "week"); var title = Weeks.Nice(wk);
            tt.Children.Add(Ui.T(title.Substring(0, 1).ToUpperInvariant() + title.Substring(1), 15, true));
            tt.Children.Add(Ui.Muted((created == null ? "" : "Written " + created.Value.ToString("ddd d MMM, HH:mm") + "  -  ") + J.Str(r, "summary"), 11.5, 0));
            head.Children.Add(tt);
            s.Children.Add(head);
            Action<string, string, Brush> line = (icon, text, color) =>
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
                var ic = Icons.Make(icon, 13, color); ic.Margin = new Thickness(0, 2, 9, 0); ic.VerticalAlignment = VerticalAlignment.Top; DockPanel.SetDock(ic, Dock.Left); row.Children.Add(ic);
                row.Children.Add(Ui.T(text, 12.5)); s.Children.Add(row);
            };
            var fixd = Items(r, "fixed"); var newi = Items(r, "newIssues"); var issues = Items(r, "issues");
            if (J.Get(r, "previousScore") != null)
            {
                line("circle-check", fixd.Count == 0 ? "Nothing fixed this week." : "Fixed: " + string.Join(", ", fixd.Select(x => J.Str(x, "title"))), fixd.Count == 0 ? Ui.R("Muted") : Ui.Green);
                line("triangle-exclamation", newi.Count == 0 ? "No new issues." : "New: " + string.Join(", ", newi.Select(x => J.Str(x, "title"))), newi.Count == 0 ? Ui.R("Muted") : Ui.Amber);
            }
            else line("circle-info", "Your first report - next week's compares with this one.", Ui.B("#7FB2F0"));
            if (full && issues.Count > 0) line("list", "Still to do: " + string.Join(", ", issues.Take(5).Select(x => J.Str(x, "title"))) + (issues.Count > 5 ? " and " + (issues.Count - 5) + " more" : ""), Ui.R("Muted"));
            var sc = J.Dict(r, "scans");
            if (sc != null)
            {
                int total = J.Int(sc, "total") ?? 0, aw = J.Int(sc, "away") ?? 0, bad = J.Int(sc, "withThreats") ?? 0;
                line("magnifying-glass", total == 0 ? "No scans by Hallow Guard." + (J.Str(sc, "defenderQuick") != null ? " Defender scanned on its own." : "") : Plural(total, "scan", "scans") + (aw > 0 ? " (" + aw + " while you were away)" : "") + (bad > 0 ? ", " + bad + " found something" : ", nothing found"), bad > 0 ? Ui.Red : Ui.R("Text"));
            }
            var th = J.Get(r, "threats");
            if (th != null) { var n = Convert.ToInt32(th); line("shield-virus", n == 0 ? "Defender found no threats." : "Defender found " + Plural(n, "threat", "threats") + " - see History.", n == 0 ? Ui.Green : Ui.Red); }
            var ch = J.Dict(r, "changes");
            if (ch != null)
            {
                int nw = J.Int(ch, "new") ?? 0, rm = J.Int(ch, "removed") ?? 0, ns = J.Int(ch, "newSuspicious") ?? 0;
                line("calendar-week", nw == 0 && rm == 0 ? "Nothing new starts with Windows or listens on the network." : Plural(nw, "new item", "new items") + (ns > 0 ? " (" + ns + " suspicious)" : "") + ", " + rm + " removed", ns > 0 ? Ui.Red : Ui.R("Text"));
                if (full)
                    foreach (var x in Items(ch, "newItems").Take(6))
                    {
                        var t = OneLine(Ui.T("+ " + J.Str(x, "name") + "   " + Snapshots.KindWord(J.Str(x, "kind") ?? "", 1) + (J.Bool(x, "suspicious") == true ? "   suspicious" : ""), 12, false, J.Bool(x, "suspicious") == true ? Ui.Red : Ui.R("Muted")));
                        t.Margin = new Thickness(22, 0, 0, 2); s.Children.Add(t);
                    }
            }
            var card = Card(s, 10); if (full) { card.BorderBrush = Ui.Hi; }
            return card;
        }
    }
}
