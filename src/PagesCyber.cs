// Hallow Guard v1.4 - the HUD looks' pages (v1.7: Hallow console, the default, and Cyber blue): the sidebar with its telemetry block, Overview (the radar ring, segmented
// sub-scores, check rows with LEDs and [OK]/[WARN]/[RISK] codes), Scan (elapsed timer, scanning beam, a live console of what
// Defender's scanner says), History (threat tags), Leftovers rows (a pulsing edge on suspicious ones), the Network page's
// connection map and Settings > Look. Same data, same buttons and the same rules as the classic pages - only the look differs.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace HallowGuard
{
    public partial class MainWindow
    {
        Action cyTick;                     // what the open cyber page updates once a second (timer, console)
        int lastRingScore = -2;            // the count-up runs when the score shown changes
        TextBlock teleUp, teleCheck, teleDefs, teleScan;
        [DllImport("kernel32.dll")] static extern ulong GetTickCount64();

        static readonly Dictionary<string, string> HudTitles = new Dictionary<string, string> {
            { "Overview", "System integrity" }, { "Scan", "Threat scan" }, { "History", "Threat log" }, { "Network", "Network surface" },
            { "Extensions", "Browser extensions" }, { "Ransomware protection", "Ransomware shield" }, { "Leftovers", "Leftovers" },
            { "Reports", "Weekly reports" }, { "Settings", "Settings" } };

        static StackPanel CyPage(string title, string sub)
        {
            var sp = new StackPanel { Margin = new Thickness(28, 18, 28, 12) };
            string hud; if (!HudTitles.TryGetValue(title, out hud)) hud = title;
            sp.Children.Add(Hud.M("GUARD://" + title.Split(' ')[0].ToLowerInvariant(), 10.5, Hud.Soft(Hud.Lilac, 0.9), 2));
            sp.Children.Add(Hud.Caps(hud, 23, Hud.Text, 0));
            sp.Children.Add(new Rectangle { Width = 56, Height = 2, Fill = Hud.Glow, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 5, 0, 12), Effect = Hud.Fx(new DropShadowEffect { Color = Hud.C(Hud.Glow), BlurRadius = 8, ShadowDepth = 0 }) });
            if (sub != null) sp.Children.Add(Ui.Muted(sub, 12.5, 14));
            return sp;
        }
        static FrameworkElement CySection(string title, string sub)
        {
            var d = new DockPanel { Margin = new Thickness(0, 14, 0, 8) };
            var mark = new Rectangle { Width = 6, Height = 6, Fill = Hud.Glow, Margin = new Thickness(0, 0, 9, 0), VerticalAlignment = VerticalAlignment.Center }; DockPanel.SetDock(mark, Dock.Left); d.Children.Add(mark);
            var t = Hud.Caps(title, 13, Hud.Text); t.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(t, Dock.Left); d.Children.Add(t);
            if (sub != null) { var s = Hud.M(sub, 10.5, Hud.Muted); s.Margin = new Thickness(12, 0, 0, 0); s.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(s, Dock.Right); d.Children.Add(s); }
            d.Children.Add(new Rectangle { Height = 1, Fill = Hud.Line, Margin = new Thickness(12, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center, SnapsToDevicePixels = true });
            return d;
        }
        static string Short(TimeSpan t)
        {
            if (t.TotalMinutes < 1) return "<1m";
            if (t.TotalHours < 1) return (int)t.TotalMinutes + "m";
            if (t.TotalDays < 1) return (int)t.TotalHours + "h " + t.Minutes.ToString("00") + "m";
            return (int)t.TotalDays + "d " + t.Hours + "h";
        }
        static string Clock(TimeSpan e) { return ((int)e.TotalHours).ToString("00") + ":" + e.Minutes.ToString("00") + ":" + e.Seconds.ToString("00"); }

        // ---------------- the frame: sidebar, hex grid, vignette
        void CyRebuild()
        {
            var root = new Grid { Background = Hud.Bg };
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(224) });
            root.ColumnDefinitions.Add(new ColumnDefinition());
            var hex = new Rectangle { Fill = Hud.HexGrid, IsHitTestVisible = false }; Grid.SetColumnSpan(hex, 2); root.Children.Add(hex);
            var vig = new Rectangle { Fill = Hud.Vignette, IsHitTestVisible = false }; Grid.SetColumnSpan(vig, 2); root.Children.Add(vig);
            // the page list
            var side = new DockPanel { LastChildFill = false };
            var sideBox = new Border { Child = side, Background = Hud.Alpha(Hud.Side, 0.92), BorderBrush = Hud.Line, BorderThickness = new Thickness(0, 0, 1, 0) };
            var head = new StackPanel { Margin = new Thickness(18, 18, 18, 18) };
            var brand = new StackPanel { Orientation = Orientation.Horizontal };
            try { brand.Children.Add(new Image { Source = Ui.AppIcon(), Width = 26, Height = 26, Margin = new Thickness(0, 0, 10, 0) }); } catch { }
            var word = new TextBlock { FontFamily = Hud.Head, FontSize = 19, VerticalAlignment = VerticalAlignment.Center };
            word.Inlines.Add(new System.Windows.Documents.Run("HALLOW") { FontWeight = FontWeights.Bold, Foreground = Ui.Accent });
            word.Inlines.Add(new System.Windows.Documents.Run(" GUARD") { FontWeight = FontWeights.Light, Foreground = Look.IsCyberBlue ? Hud.Glow : Hud.Text });
            brand.Children.Add(word); head.Children.Add(brand);
            var tag = Hud.M("SECURITY CONSOLE // v" + Program.Version, 10, Hud.Muted, 0); tag.Margin = new Thickness(36, 2, 0, 0); head.Children.Add(tag);
            DockPanel.SetDock(head, Dock.Top); side.Children.Add(head);
            nav.Clear(); int n = 0;
            foreach (var p in new[] { Tuple.Create("overview", "Overview", "shield-halved"), Tuple.Create("scan", "Scan", "magnifying-glass"), Tuple.Create("history", "History", "clock-rotate-left"),
                Tuple.Create("network", "Network", "globe"), Tuple.Create("extensions", "Extensions", "puzzle-piece"), Tuple.Create("ransomware", "Ransomware", "lock"),
                Tuple.Create("hardening", "Hardening", "user-shield"), Tuple.Create("leftovers", "Leftovers", "broom"), Tuple.Create("reports", "Reports", "chart-line"), Tuple.Create("settings", "Settings", "gear") })
            {
                var id = p.Item1; n++;
                var ct = new StackPanel { Orientation = Orientation.Horizontal };
                ct.Children.Add(new TextBlock { Text = n.ToString("00"), FontFamily = Hud.Mono, FontSize = 9.5, Foreground = Hud.Soft(Hud.Lilac, 0.6), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) });
                var ic = Icons.Make(p.Item3, 14, Hud.Alpha(Hud.Lilac, 0.95)); ic.Margin = new Thickness(0, 0, 11, 0); ic.VerticalAlignment = VerticalAlignment.Center; ct.Children.Add(ic);
                ct.Children.Add(new TextBlock { Text = Hud.Spaced(p.Item2), FontFamily = Hud.Head, FontSize = 12.5, VerticalAlignment = VerticalAlignment.Center });
                var b = new Button { Style = Ui.S("Nav"), Content = ct, Margin = new Thickness(0, 0, 10, 0) };
                AutomationProperties.SetName(b, p.Item2);
                b.Click += (s, e) => Show(id);
                DockPanel.SetDock(b, Dock.Top); side.Children.Add(b); nav[id] = b;
            }
            var foot = new StackPanel { Margin = new Thickness(14, 0, 14, 14) };
            updateBtn = Ui.Btn("Update", () => c.InstallUpdate(), true); updateBtn.Visibility = c.PendingUpdate == null ? Visibility.Collapsed : Visibility.Visible; updateBtn.HorizontalAlignment = HorizontalAlignment.Left; updateBtn.Margin = new Thickness(0, 0, 0, 10);
            if (c.PendingUpdate != null) updateBtn.Content = "Update to v" + c.PendingUpdate.Version.ToString(2);
            foot.Children.Add(updateBtn);
            foot.Children.Add(Telemetry());
            foot.Children.Add(Ui.Muted("Uses Microsoft Defender's engine - not an antivirus of its own.", 10.5, 0));
            DockPanel.SetDock(foot, Dock.Bottom); side.Children.Add(foot);
            root.Children.Add(sideBox);
            // the page
            var right = new DockPanel(); Grid.SetColumn(right, 1);
            state = new TextBlock { FontFamily = Hud.Mono, FontSize = 11.5, Foreground = Hud.Muted, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(28, 6, 28, 12) };
            DockPanel.SetDock(state, Dock.Bottom); right.Children.Add(state);
            content = new Border(); right.Children.Add(content);
            root.Children.Add(right);
            Content = root;
            Show(page);
        }
        FrameworkElement Telemetry()
        {
            var g = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); g.ColumnDefinitions.Add(new ColumnDefinition());
            var hd = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
            var led = Hud.Led(Hud.Green, 6); led.Margin = new Thickness(-4, 0, 2, 0); hd.Children.Add(led);
            hd.Children.Add(Hud.Caps("Telemetry", 10, Hud.Glow));
            Grid.SetColumnSpan(hd, 2); g.Children.Add(hd);
            g.RowDefinitions.Add(new RowDefinition());
            Func<string, TextBlock> row = key =>
            {
                g.RowDefinitions.Add(new RowDefinition()); int r = g.RowDefinitions.Count - 1;
                var k = Hud.M(key, 10, Hud.Muted); k.Margin = new Thickness(0, 0, 10, 2); Grid.SetRow(k, r); g.Children.Add(k);
                var v = Hud.M("--", 10, Hud.Text); v.TextAlignment = TextAlignment.Right; Grid.SetRow(v, r); Grid.SetColumn(v, 1); g.Children.Add(v);
                return v;
            };
            teleUp = row("UPTIME"); teleCheck = row("LAST CHECK"); teleDefs = row("DEFS AGE"); teleScan = row("ENGINE");
            UpdateTelemetry();
            var box = new Border { Child = g, BorderBrush = Hud.Line, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(0, 10, 0, 0) };
            return box;
        }
        void UpdateTelemetry()
        {
            if (teleUp == null) return;
            var up = Snap.On ? new TimeSpan(2, 6, 41, 9) : TimeSpan.FromMilliseconds(GetTickCount64());
            teleUp.Text = (int)up.TotalDays + "d " + up.Hours.ToString("00") + ":" + up.Minutes.ToString("00") + ":" + up.Seconds.ToString("00");
            teleCheck.Text = c.Checking ? "RUNNING" : c.CheckedAt == null ? "--" : Short(DateTime.Now - c.CheckedAt.Value) + " ago";
            var age = c.Facts == null ? null : c.Facts.SigAgeDays;
            teleDefs.Text = age == null ? "--" : age.Value + "d"; teleDefs.Foreground = age == null ? Hud.Muted : age.Value >= 8 ? Hud.Red : age.Value >= 3 ? Hud.Amber : Hud.Green;
            teleScan.Text = c.Scanning ? "SCANNING" : "DEFENDER"; teleScan.Foreground = c.Scanning ? Hud.Amber : Hud.Glow;
        }

        // ---------------- Overview
        Action<bool> CountUp(Hud.Radar r, int score)
        {
            bool started = false; DispatcherTimer t = null; var built = DateTime.Now;
            return run =>
            {
                if (run && !started && (DateTime.Now - built).TotalSeconds < 2.5)
                {
                    started = true; var sw = Stopwatch.StartNew();
                    t = new DispatcherTimer(DispatcherPriority.Render) { Interval = TimeSpan.FromMilliseconds(33) };
                    t.Tick += (s, e) =>
                    {
                        double k = Math.Min(1, sw.ElapsedMilliseconds / 950.0); k = 1 - Math.Pow(1 - k, 3);
                        int v = (int)Math.Round(score * k); r.Number.Text = v.ToString(); r.Show(v);
                        if (k >= 1) { t.Stop(); t = null; }
                    };
                    r.Number.Text = "0"; r.Show(0); t.Start();
                }
                else if (!run && t != null) { t.Stop(); t = null; r.Number.Text = score.ToString(); r.Show(score); }
            };
        }
        FrameworkElement CyOverviewPage()
        {
            var sp = Page("Overview", null);
            int score = c.FamilyValue >= 0 ? c.FamilyValue : c.ScoreValue;
            var col = score < 0 ? Hud.Glow : Hud.ScoreColor(score);
            var top = new Grid();
            top.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); top.ColumnDefinitions.Add(new ColumnDefinition());
            var radar = new Hud.Radar(score, 200, c.Checking || c.Scanning || score < 0 || Snap.On);   // snapshots show the sweep mid-turn
            radar.View.Margin = new Thickness(0, 0, 26, 0); radar.View.VerticalAlignment = VerticalAlignment.Center; top.Children.Add(radar.View);
            Anim.Add(radar.Sweep); Anim.Add(radar.Pulse);
            if (score >= 0 && score != lastRingScore && !Snap.On) Anim.Add(CountUp(radar, score));
            lastRingScore = score;
            var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center }; Grid.SetColumn(info, 1);
            var st = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
            var led = Hud.Led(col, 9); led.Margin = new Thickness(-6, 0, 2, 0); st.Children.Add(led);
            st.Children.Add(Hud.M("STATUS: ", 12.5, Hud.Muted));
            var sv = Hud.M(c.Checking && score < 0 ? "CHECKING" : Hud.Status(score), 12.5, col); sv.FontWeight = FontWeights.Bold; st.Children.Add(sv);
            if (c.CheckedAt != null) { var ck = Hud.M("   //   CHECKED " + Short(DateTime.Now - c.CheckedAt.Value).ToUpperInvariant() + " AGO", 10.5, Hud.Muted); ck.VerticalAlignment = VerticalAlignment.Center; st.Children.Add(ck); }
            AutomationProperties.SetName(st, "Status: " + Hud.Status(score));
            info.Children.Add(st);
            info.Children.Add(new TextBlock { Text = score < 0 ? "Checking your PC..." : Score.Label(score), FontFamily = Hud.Head, FontSize = 26, FontWeight = FontWeights.SemiBold, Foreground = col, Margin = new Thickness(0, 0, 0, 4) });
            var todo = c.Todo();
            info.Children.Add(Ui.Muted(c.Checks == null ? "Reading Windows Security, system settings and your Hallow apps - nothing is changed." : (todo.Count == 0 ? "Everything Hallow Guard checks is in good shape." : "One score for the whole PC: Windows, your Hallow apps, the network and your browsers."), 12.5, 10));
            if (c.ScoreValue >= 0)
            {
                info.Children.Add(Hud.SegBar("Windows", c.ScoreValue));
                info.Children.Add(Hud.SegBar("Hallow apps", c.AppsValue));
                info.Children.Add(Hud.SegBar("Network & browsers", c.MoreValue));
                info.Children.Add(Hud.SegBar("Hardening", c.HardValue));
            }
            var again = Ui.Btn(c.Checking ? "Checking..." : "Check again", () => c.RefreshChecks()); again.IsEnabled = !c.Checking;
            var quick = Ui.Btn(c.Scanning ? "Scanning..." : "Quick scan", () => { var e = c.StartScan("quick", null); if (e != null) Say(e); else Show("scan"); }, true); quick.IsEnabled = !c.Scanning;
            var btns = Ui.Row(quick, again); btns.Margin = new Thickness(0, 8, 0, 0); info.Children.Add(btns);
            top.Children.Add(info);
            sp.Children.Add(Hud.Card(top, new Thickness(18, 16, 18, 16), 6));
            // the one to-do list
            if (c.Checks != null)
            {
                sp.Children.Add(Section("To do", todo.Count == 0 ? "nothing to fix" : "the " + (todo.Count == 1 ? "thing" : todo.Count + " things") + " worth the most points first"));
                if (todo.Count == 0) sp.Children.Add(Card(CyLine(Hud.Green, "[CLEAR]", "Nothing to fix right now."), 8));
                else sp.Children.Add(CyGroup(todo, true));
            }
            if (c.Checks != null) { sp.Children.Add(Section("Windows", c.ScoreValue + " / 100")); sp.Children.Add(CyGroup(Ordered(c.Checks), false)); }
            if (c.AppChecks != null)
            {
                sp.Children.Add(Section("Hallow apps", c.AppsValue == null ? "none installed - each one is optional" : c.AppsValue + " / 100"));
                sp.Children.Add(CyGroup(c.AppChecks.OrderBy(x => x.NotInstalled ? 1 : 0).ThenBy(x => Rank(x.State)), false));
                sp.Children.Add(Ui.Muted("Hallow apps that aren't installed never cost points. Installed ones can take off a few: Hallow Keys up to " + FamilyScore.KeysMax + " (counts only - Guard never opens your vault), Hallow Vault up to " + FamilyScore.VaultMax + ", Hallow Shield 2; the family score is the Windows score minus those points (at most " + FamilyScore.AppsCap + ").", 11.5, 8));
            }
            if (c.MoreChecks != null)
            {
                sp.Children.Add(Section("Network & browsers", c.MoreValue + " / 100"));
                sp.Children.Add(CyGroup(Ordered(c.MoreChecks), false));
                sp.Children.Add(Ui.Muted("A suspicious program open to the network costs " + NetView.SuspiciousPoints + " points, each high-risk browser extension " + ExtScan.HighPoints + " (at most " + ExtScan.MaxPoints + "); this group takes at most " + MoreScore.Cap + " off the family score.", 11.5, 8));
            }
            HardeningSummary(sp);
            sp.Children.Add(Ui.Muted("Hallow Guard only reads these. \"Open settings\" takes you to the right Windows page; nothing is changed behind your back.", 11.5, 0));
            return sp;
        }
        static FrameworkElement CyLine(Brush color, string code, string text)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            var led = Hud.Led(color, 8); led.Margin = new Thickness(-6, 0, 4, 0); row.Children.Add(led);
            var cd = Hud.M(code, 11.5, color); cd.FontWeight = FontWeights.Bold; cd.VerticalAlignment = VerticalAlignment.Center; cd.Margin = new Thickness(0, 0, 10, 0); row.Children.Add(cd);
            var t = Ui.T(text, 13); t.VerticalAlignment = VerticalAlignment.Center; row.Children.Add(t);
            return row;
        }
        // one card, one row per check, thin lines between
        FrameworkElement CyGroup(IEnumerable<Check> checks, bool numbered)
        {
            var s = new StackPanel(); int i = 0;
            foreach (var ch in checks)
            {
                if (i++ > 0) s.Children.Add(Hud.Divider(9, 9));
                s.Children.Add(CyCheckRow(ch, numbered ? i : 0));
            }
            return Hud.Card(s, new Thickness(14, 12, 16, 12), 8);
        }
        FrameworkElement CyCheckRow(Check ch, int num)
        {
            var row = new DockPanel();
            var color = ch.NotInstalled ? Hud.Muted : Hud.StateColor(ch.State);
            var left = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Top };
            if (num > 0)
            {
                var nb = new Border { BorderBrush = color, BorderThickness = new Thickness(1), Background = Hud.Alpha(color, Mode.IsLight ? 0.08 : 0.12), Width = 28, Height = 22, Margin = new Thickness(0, 0, 8, 0), VerticalAlignment = VerticalAlignment.Top };
                nb.Child = new TextBlock { Text = num.ToString("00"), FontFamily = Hud.Mono, FontSize = 11, FontWeight = FontWeights.Bold, Foreground = color, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                left.Children.Add(nb);
            }
            var led = Hud.Led(color, 8); led.VerticalAlignment = VerticalAlignment.Top; led.Margin = new Thickness(-4, -1, 2, 0); left.Children.Add(led);
            var code = Hud.M(Hud.Code(ch.State, ch.NotInstalled), 11.5, color); code.FontWeight = FontWeights.Bold; code.Width = 52; code.Margin = new Thickness(0, 2, 6, 0); left.Children.Add(code);
            DockPanel.SetDock(left, Dock.Left); row.Children.Add(left);
            if (ch.FixLabel != null) { var fb = FixButton(ch, num > 0); fb.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(fb, Dock.Right); row.Children.Add(fb); }
            var txt = new StackPanel();
            var head = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 2) };
            head.Children.Add(Ui.T(ch.Title, 13.5, true));
            if (ch.Penalty > 0) { var pts = Hud.M("+" + ch.Penalty + (ch.Penalty == 1 ? " PT" : " PTS"), 10.5, color); pts.VerticalAlignment = VerticalAlignment.Center; pts.Margin = new Thickness(10, 1, 0, 0); head.Children.Add(pts); }
            if (ch.NotInstalled) { var chip = Hud.Tag("Not installed", Hud.Muted); chip.Margin = new Thickness(10, 0, 0, 0); head.Children.Add(chip); }
            txt.Children.Add(head);
            txt.Children.Add(Ui.Muted(ch.NotInstalled && ch.Line.StartsWith("Not installed. ") ? ch.Line.Substring(15) : ch.Line, 12.5));
            row.Children.Add(txt);
            AutomationProperties.SetName(row, Hud.Code(ch.State, ch.NotInstalled) + " " + ch.Title);
            return row;
        }

        // ---------------- Scan
        FrameworkElement CyScanPage()
        {
            var sp = Page("Scan", "Microsoft Defender does the scanning - Hallow Guard asks it to and shows you the result. You can keep using the PC while it runs.");
            var grid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            for (int i = 0; i < 3; i++) { grid.ColumnDefinitions.Add(new ColumnDefinition()); if (i < 2) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(10) }); }
            bool busy = c.Scanning;
            Func<string, string, string, string, Button, FrameworkElement> tile = (icon, code, title, text, btn) =>
            {
                var s = new DockPanel { LastChildFill = false };
                var h = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
                var ic = Icons.Make(icon, 17, Hud.Glow); ic.Margin = new Thickness(0, 0, 9, 0); DockPanel.SetDock(ic, Dock.Left); h.Children.Add(ic);
                var cd = Hud.M(code, 9.5, Hud.Soft(Hud.Lilac, 0.85)); cd.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(cd, Dock.Right); h.Children.Add(cd);
                h.Children.Add(Ui.T(title, 14.5, true));
                DockPanel.SetDock(h, Dock.Top); s.Children.Add(h); var tx = Ui.Muted(text, 12, 10); DockPanel.SetDock(tx, Dock.Top); s.Children.Add(tx);
                btn.HorizontalAlignment = HorizontalAlignment.Left; DockPanel.SetDock(btn, Dock.Bottom); s.Children.Add(btn);
                return Card(s, 0);
            };
            var q = Ui.Btn("Quick scan", () => Start("quick", null), true); q.IsEnabled = !busy;
            var f = Ui.Btn("Full scan", () => Start("full", null)); f.IsEnabled = !busy;
            var fo = Ui.Btn("Choose a folder", PickFolder); fo.IsEnabled = !busy;
            var t1 = tile("bolt", "TYPE 1", "Quick scan", "The places malware usually hides. A few minutes.", q);
            var t2 = tile("hard-drive", "TYPE 2", "Full scan", "Every file on every drive. Can take an hour or more.", f); Grid.SetColumn(t2, 2);
            var t3 = tile("folder-open", "TYPE 3", "A folder", "Just the folder you pick, like a USB stick.", fo); Grid.SetColumn(t3, 4);
            grid.Children.Add(t1); grid.Children.Add(t2); grid.Children.Add(t3);
            sp.Children.Add(grid);
            // drop target
            var drop = new Grid { Margin = new Thickness(0, 0, 0, 10), MinHeight = 64, AllowDrop = true, Background = Hud.Alpha(Hud.Glow, 0.03) };
            drop.Children.Add(new Rectangle { Stroke = Hud.Alpha(Hud.Lilac, 0.45), StrokeThickness = 1, StrokeDashArray = new DoubleCollection { 6, 4 }, RadiusX = 2, RadiusY = 2 });
            var dropRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            var dic = Icons.Make("file-shield", 20, Hud.Glow); dic.Margin = new Thickness(0, 0, 12, 0); dropRow.Children.Add(dic);
            var dt = Hud.M("DROP A FILE HERE TO SCAN IT", 12, Hud.Text); dt.VerticalAlignment = VerticalAlignment.Center; dropRow.Children.Add(dt);
            var pick = Ui.Btn("Choose a file", PickFile); pick.Margin = new Thickness(16, 0, 0, 0); pick.IsEnabled = !busy; dropRow.Children.Add(pick);
            drop.Children.Add(dropRow);
            drop.DragOver += (s, e) => { e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) && !c.Scanning ? DragDropEffects.Copy : DragDropEffects.None; e.Handled = true; };
            drop.Drop += (s, e) => { var files = e.Data.GetData(DataFormats.FileDrop) as string[]; if (files != null && files.Length > 0) Start("custom", files[0]); };
            sp.Children.Add(drop);
            if (busy) sp.Children.Add(ScanConsoleCard(c.Current));
            else if (c.LastScanMessage != null)
            {
                var good = c.LastScanMessage.Contains("nothing found"); var found = !good && c.LastScanMessage.Contains("found");
                sp.Children.Add(Card(CyLine(good ? Hud.Green : found ? Hud.Red : Hud.Amber, good ? "[CLEAN]" : found ? "[FOUND]" : "[INFO]", c.LastScanMessage)));
            }
            // Watch Downloads
            var w = new StackPanel();
            w.Children.Add(Ui.Switch("Watch Downloads - scan each new download as soon as it has finished", c.S.WatchDownloads, v => c.SetWatch(v)));
            var where = Snap.On ? @"C:\Users\Alex\Downloads" : DownloadWatcher.DownloadsFolder();
            w.Children.Add(Ui.Muted("Off by default. Hallow Guard waits until a file stops growing (and skips .crdownload / .part files), then asks Defender to check just that file. You only hear from it if something is found.", 11.5, 4));
            w.Children.Add(Hud.M("WATCHING  " + where, 10.5, Hud.Soft(Hud.Lilac, 0.95), 4));
            List<string> wl; lock (c.WatchLog) wl = c.WatchLog.ToList();
            foreach (var l in wl.Take(5)) w.Children.Add(Mono("> " + l, l.Contains("THREAT") ? Hud.Red : Hud.Muted));
            sp.Children.Add(Card(w));
            // recent scans: a small table
            List<ScanRecord> scans; lock (c.S.Scans) scans = c.S.Scans.Take(8).ToList();
            if (scans.Count > 0)
            {
                sp.Children.Add(Section("Recent scans", "by Hallow Guard"));
                var tb = new StackPanel(); int i = 0;
                foreach (var r in scans)
                {
                    if (i++ > 0) tb.Children.Add(Hud.Divider(5, 5));
                    var row = new DockPanel();
                    var ok = r.Result == "clean"; var bad = r.Result == "threats";
                    var res = Hud.M(ok ? "[CLEAN]" : bad ? "[" + r.Threats + " FOUND]" : "[" + (r.Result ?? "?").ToUpperInvariant() + "]", 11, ok ? Hud.Green : bad ? Hud.Red : Hud.Muted); res.FontWeight = FontWeights.Bold;
                    res.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(res, Dock.Right); row.Children.Add(res);
                    var when = Iso(r.End); var wt = Hud.M(when == null ? "----------" : when.Value.ToString("yyyy-MM-dd HH:mm"), 11, Hud.Muted); wt.Width = 128; DockPanel.SetDock(wt, Dock.Left); row.Children.Add(wt);
                    var kd = Hud.M((r.Away ? "AWAY" : (r.Kind ?? "").ToUpperInvariant()), 11, Hud.Lilac); kd.Width = 84; DockPanel.SetDock(kd, Dock.Left); row.Children.Add(kd);
                    row.Children.Add(OneLine(Ui.T(r.Kind == "quick" ? "Quick scan" : r.Kind == "full" ? "Full scan" : r.Kind == "download" ? "Download: " + System.IO.Path.GetFileName(r.Target) : "Folder/file: " + r.Target, 12)));
                    tb.Children.Add(row);
                }
                sp.Children.Add(Card(tb));
            }
            return sp;
        }
        // the running scan: a big timer, the beam, and a console of what Defender's scanner says
        FrameworkElement ScanConsoleCard(ScanJob j)
        {
            var p = new StackPanel();
            var hdr = new DockPanel { Margin = new Thickness(0, 0, 0, 10) };
            var cancel = Ui.Btn("Cancel", () => { c.CancelScan(); Say("Cancelling..."); }); DockPanel.SetDock(cancel, Dock.Right); hdr.Children.Add(cancel);
            var led = Hud.Led(Hud.Amber, 8); led.Margin = new Thickness(-6, 0, 2, 0); DockPanel.SetDock(led, Dock.Left); hdr.Children.Add(led);
            Anim.Add(Hud.Animate(led, UIElement.OpacityProperty, () => Hud.Loop(1, 0.25, 0.7, true), 1));
            var what = j.Kind == "quick" ? "Quick scan running" : j.Kind == "full" ? "Full scan running" : j.Kind == "download" ? "Checking a new download" : "Scanning a folder or file";
            var title = Hud.Caps(what, 14, Hud.Glow); title.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(title, Dock.Left); hdr.Children.Add(title);
            var tgt = Hud.M(j.Target == null ? "" : "   " + j.Target, 11, Hud.Muted); tgt.VerticalAlignment = VerticalAlignment.Center; hdr.Children.Add(tgt);
            p.Children.Add(hdr);
            // timer + facts
            var g = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); g.ColumnDefinitions.Add(new ColumnDefinition());
            var tl = new StackPanel { Margin = new Thickness(0, 0, 28, 0) };
            var timer = new TextBlock { Text = Clock(j.Elapsed), FontFamily = Hud.Mono, FontSize = 40, FontWeight = FontWeights.SemiBold, Foreground = Hud.Text, Effect = Hud.Fx(new DropShadowEffect { Color = Hud.C(Hud.Glow), BlurRadius = 14, ShadowDepth = 0, Opacity = 0.6 }) };
            AutomationProperties.SetName(timer, "Elapsed time");
            tl.Children.Add(Hud.M("ELAPSED", 10, Hud.Muted)); tl.Children.Add(timer);
            tl.Children.Add(Hud.M(j.Kind == "full" ? "a full scan can take an hour or more" : j.Kind == "quick" ? "usually a few minutes" : "one folder or file", 10.5, Hud.Muted));
            g.Children.Add(tl);
            var facts = new Grid { VerticalAlignment = VerticalAlignment.Center }; Grid.SetColumn(facts, 1);
            facts.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); facts.ColumnDefinitions.Add(new ColumnDefinition());
            Action<string, string, Brush> fact = (k, v, b) =>
            {
                facts.RowDefinitions.Add(new RowDefinition()); int r = facts.RowDefinitions.Count - 1;
                var kt = Hud.M(k, 10.5, Hud.Muted); kt.Margin = new Thickness(0, 0, 14, 3); Grid.SetRow(kt, r); facts.Children.Add(kt);
                var vt = Hud.M(v, 10.5, b); Grid.SetRow(vt, r); Grid.SetColumn(vt, 1); facts.Children.Add(vt);
            };
            fact("ENGINE", "Microsoft Defender  (MpCmdRun.exe)", Hud.Text);
            fact("SCAN TYPE", j.Kind == "quick" ? "1 / QUICK" : j.Kind == "full" ? "2 / FULL" : "3 / " + (j.Kind == "download" ? "DOWNLOAD" : "CUSTOM"), Hud.Glow);
            fact("PRIORITY", j.Low ? "IDLE (you're away)" : "NORMAL", Hud.Text);
            fact("STARTED", j.Start.ToString("HH:mm:ss"), Hud.Text);
            g.Children.Add(facts);
            p.Children.Add(g);
            p.Children.Add(Beam());
            // the console
            var con = new StackPanel();
            var conBox = new Border { Child = con, Background = Hud.Console, BorderBrush = Hud.Line, BorderThickness = new Thickness(1), Padding = new Thickness(12, 9, 12, 9), Height = 176, Margin = new Thickness(0, 12, 0, 6), ClipToBounds = true };
            var cursor = new TextBlock { Text = "\u2588", FontFamily = Hud.Mono, FontSize = 11.5, Foreground = Hud.Glow };
            var blink = new DoubleAnimationUsingKeyFrames { Duration = TimeSpan.FromSeconds(1.1), RepeatBehavior = RepeatBehavior.Forever };
            blink.KeyFrames.Add(new DiscreteDoubleKeyFrame(1, KeyTime.FromTimeSpan(TimeSpan.Zero))); blink.KeyFrames.Add(new DiscreteDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromSeconds(0.55))));
            Anim.Add(run => { if (run) cursor.BeginAnimation(UIElement.OpacityProperty, blink); else { cursor.BeginAnimation(UIElement.OpacityProperty, null); cursor.Opacity = 1; } });
            int lastCount = -1;
            Action fill = () =>
            {
                var lines = ConsoleLines(j, DateTime.Now);
                if (lines.Count == lastCount && !Snap.On && lastCount >= 0) return;
                lastCount = lines.Count; con.Children.Clear();
                foreach (var l in lines.Skip(Math.Max(0, lines.Count - 9)))
                {
                    var tb = new TextBlock { FontFamily = Hud.Mono, FontSize = 11.5, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 0, 0, 2) };
                    tb.Inlines.Add(new System.Windows.Documents.Run("[" + l.Item1.ToString("HH:mm:ss") + "] ") { Foreground = Hud.Soft(Hud.Muted, 0.9) });
                    tb.Inlines.Add(new System.Windows.Documents.Run(l.Item2.PadRight(9)) { Foreground = l.Item2 == "DEFENDER" ? Hud.Green : Hud.Lilac });
                    tb.Inlines.Add(new System.Windows.Documents.Run("> " + l.Item3) { Foreground = l.Item3.IndexOf("threat", StringComparison.OrdinalIgnoreCase) >= 0 && l.Item3.IndexOf("no threat", StringComparison.OrdinalIgnoreCase) < 0 ? Hud.Red : Hud.Text });
                    con.Children.Add(tb);
                }
                var cl = new StackPanel { Orientation = Orientation.Horizontal };
                cl.Children.Add(new TextBlock { Text = "[" + DateTime.Now.ToString("HH:mm:ss") + "] GUARD    > ", FontFamily = Hud.Mono, FontSize = 11.5, Foreground = Hud.Soft(Hud.Muted, 0.9) });
                cl.Children.Add(cursor); con.Children.Add(cl);
            };
            fill();
            var sv = new Grid(); sv.Children.Add(conBox);
            sv.Children.Add(new Rectangle { Fill = Hud.Scanlines, Opacity = 0.35, IsHitTestVisible = false, Margin = new Thickness(1, 13, 1, 7) });
            p.Children.Add(sv);
            p.Children.Add(Ui.Muted("Defender's scanner doesn't report a percentage while it works - Hallow Guard shows what it says, and that it's still running.", 11, 0));
            cyTick = () => { if (!c.Scanning) return; timer.Text = Clock(j.Elapsed); fill(); };
            return Hud.Card(p, new Thickness(16, 14, 16, 12), 10, Hud.Amber);
        }
        // time, source, text: what Guard asked for, what MpCmdRun printed, and a heartbeat each minute while it still runs
        public static List<Tuple<DateTime, string, string>> ConsoleLines(ScanJob j, DateTime now)
        {
            var l = new List<Tuple<DateTime, string, string>>();
            string args; try { args = MpCmd.Args(j.Kind, j.Target); } catch { args = "-Scan"; }
            var exe = j.Exe; var plat = exe == null ? (Snap.On ? "4.18.25090.3002" : null) : System.IO.Path.GetFileName(System.IO.Path.GetDirectoryName(exe));
            l.Add(Tuple.Create(j.Start, "GUARD", "engine  MpCmdRun.exe" + (plat != null && char.IsDigit(plat.FirstOrDefault()) ? "  (Defender platform " + plat + ")" : "")));
            l.Add(Tuple.Create(j.Start, "GUARD", "exec    MpCmdRun " + args));
            if (j.Low) l.Add(Tuple.Create(j.Start, "GUARD", "priority idle - stops when you come back"));
            lock (j.Lines)
                for (int i = 0; i < j.Lines.Count; i++)
                {
                    var t = (j.Lines[i] ?? "").Trim(); if (t.Length == 0 || t.StartsWith("---")) continue;
                    l.Add(Tuple.Create(i < j.Times.Count ? j.Times[i] : now, "DEFENDER", t));
                }
            int mins = (int)((now - j.Start).TotalMinutes);
            for (int m = Math.Max(1, mins - 5); m <= mins; m++) l.Add(Tuple.Create(j.Start.AddMinutes(m), "GUARD", "scanner still running  +" + Clock(TimeSpan.FromMinutes(m))));
            if (j.Done) l.Add(Tuple.Create(now, "GUARD", "finished: " + (j.Result ?? "?")));
            return l.OrderBy(x => x.Item1).ToList();
        }
        // a scanning beam over scanlines (Defender gives no percentage, so it's a sweep, not a fill)
        FrameworkElement Beam()
        {
            var g = new Grid { Height = 14, ClipToBounds = true };
            g.Children.Add(new Rectangle { Fill = Hud.Well, Stroke = Hud.Line, StrokeThickness = 1 });
            var beam = new LinearGradientBrush { StartPoint = new Point(0, 0.5), EndPoint = new Point(1, 0.5) };
            var gc = Hud.C(Hud.Glow); var hot = Hud.Mix(gc, Colors.White, 0.75);
            beam.GradientStops.Add(new GradientStop(Color.FromArgb(0, gc.R, gc.G, gc.B), 0.2)); beam.GradientStops.Add(new GradientStop(Color.FromArgb(120, gc.R, gc.G, gc.B), 0.44));
            beam.GradientStops.Add(new GradientStop(hot, 0.5)); beam.GradientStops.Add(new GradientStop(Color.FromArgb(0, gc.R, gc.G, gc.B), 0.53));
            var tr = new TranslateTransform(-0.08, 0); beam.RelativeTransform = tr;
            g.Children.Add(new Rectangle { Fill = beam, Margin = new Thickness(1) });
            g.Children.Add(new Rectangle { Fill = Hud.Scanlines, Margin = new Thickness(1) });
            // ticks every 10%
            var ticks = new UniformGrid { Rows = 1, Columns = 10, IsHitTestVisible = false };
            for (int i = 0; i < 10; i++) ticks.Children.Add(new Rectangle { Width = 1, HorizontalAlignment = HorizontalAlignment.Left, Fill = Hud.Alpha(Hud.Lilac, i == 0 ? 0 : 0.3) });
            g.Children.Add(ticks);
            Anim.Add(Hud.Animate(tr, TranslateTransform.XProperty, () => Hud.Loop(-0.55, 0.5, 2.6), -0.08));
            AutomationProperties.SetName(g, "Scanning");
            return g;
        }

        // ---------------- History
        FrameworkElement CyHistoryPage()
        {
            var sp = Page("History", "What Microsoft Defender has found on this PC, in plain words. To restore or remove something, use Windows Security.");
            var top = Ui.Row(Ui.Btn("Open in Windows Security", () => c.RunFix("windowsdefender://history")), Ui.Btn(c.ThreatsLoading ? "Loading..." : "Refresh", () => c.RefreshThreats()));
            top.Margin = new Thickness(0, 0, 0, 12); sp.Children.Add(top);
            if (c.ThreatError != null) { sp.Children.Add(Card(CyLine(Hud.Amber, "[ERR]", c.ThreatError))); return sp; }
            if (c.ThreatList == null) { sp.Children.Add(Hud.M("READING DEFENDER'S HISTORY...", 11.5, Hud.Muted)); return sp; }
            if (c.ThreatList.Count == 0) { sp.Children.Add(Card(CyLine(Hud.Green, "[CLEAR]", "Defender hasn't found anything on this PC."))); return sp; }
            var sum = new WrapPanel { Margin = new Thickness(0, 0, 0, 4) };
            sum.Children.Add(Hud.Tag(c.ThreatList.Count + (c.ThreatList.Count == 1 ? " record" : " records"), Hud.Glow));
            int hi = c.ThreatList.Count(t => t.Severity >= 4), open = c.ThreatList.Count(t => ThreatOpen(t));
            if (hi > 0) sum.Children.Add(Hud.Tag(hi + " high / severe", Hud.Red));
            sum.Children.Add(Hud.Tag(open == 0 ? "all dealt with" : open + " need a look", open == 0 ? Hud.Green : Hud.Amber));
            sp.Children.Add(sum);
            sp.Children.Add(Section("Threat log", "newest first"));
            foreach (var t in c.ThreatList)
            {
                var s = new StackPanel();
                var sevCol = t.Severity >= 4 ? Hud.Red : t.Severity == 2 ? Hud.Amber : t.Severity == 1 ? Hud.Low : Hud.Muted;
                var h = new DockPanel { Margin = new Thickness(0, 0, 0, 5) };
                var sev = Hud.Tag("SEV:" + t.SeverityText, sevCol); DockPanel.SetDock(sev, Dock.Left); h.Children.Add(sev);
                var when = Hud.M(t.When == null ? "----" : t.When.Value.ToString("yyyy-MM-dd HH:mm"), 11, Hud.Muted); when.VerticalAlignment = VerticalAlignment.Center; when.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(when, Dock.Right); h.Children.Add(when);
                var nm = OneLine(Ui.T(t.Kind + "  -  " + t.Name, 13.5, true)); nm.VerticalAlignment = VerticalAlignment.Center; h.Children.Add(nm);
                s.Children.Add(h);
                s.Children.Add(Hud.M("THREAT-ID 0x" + t.Id.ToString("X8") + "   CAT " + t.Category.ToString("00") + "   STATUS " + t.StatusId.ToString("00"), 10.5, Hud.Soft(Hud.Lilac, 0.95), 5));
                s.Children.Add(Ui.T(t.What, 12.5, false, null, 4));
                bool bad = ThreatOpen(t);
                var act = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
                var ac = Hud.M(bad ? "[ACTION]" : "[CONTAINED]", 11, bad ? Hud.Amber : Hud.Green); ac.FontWeight = FontWeights.Bold; ac.Margin = new Thickness(0, 0, 8, 0); act.Children.Add(ac);
                act.Children.Add(Ui.T(t.Action, 12.5, false, bad ? Hud.Amber : Hud.Green)); s.Children.Add(act);
                foreach (var p in t.Paths.Take(3)) s.Children.Add(Mono("> " + p, Hud.Muted));
                var first = t.Paths.FirstOrDefault();
                var btns = Ui.Row(Ui.Btn("Open in Windows Security", () => c.RunFix("windowsdefender://history")));
                if (first != null && first.Contains(":\\")) btns.Children.Add(Ui.Btn("Open file location", () => Controller.OpenLocation(first)));
                btns.Margin = new Thickness(0, 8, 0, 0); s.Children.Add(btns);
                var card = Card(s, 10);
                if (t.Severity >= 4) PulseEdge(card, Hud.Red, bad);
                sp.Children.Add(card);
            }
            return sp;
        }
        static bool ThreatOpen(ThreatRecord t) { return t.Action.Contains("couldn't") || t.Action.Contains("waiting") || t.StatusId == 5; }
        // a red edge on the card's left side; it pulses (while animations may run) when asked to
        void PulseEdge(Border card, Brush color, bool pulse)
        {
            card.BorderBrush = Hud.Alpha(color, 0.65);
            var g = card.Child as Grid; if (g == null) return;
            var edge = new Rectangle { Width = 3, Fill = color, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(-1, 6, 0, 6), IsHitTestVisible = false, Effect = Hud.Fx(new DropShadowEffect { Color = Hud.C(color), BlurRadius = 10, ShadowDepth = 0, Opacity = 0.9 }) };
            g.Children.Add(edge);
            if (pulse) Anim.Add(Hud.Animate(edge, UIElement.OpacityProperty, () => Hud.Loop(1, 0.3, 0.9, true), 1));
        }

        // ---------------- Leftovers row
        FrameworkElement CyLeftoverRow(Leftover l)
        {
            var s = new StackPanel();
            var h = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
            var chip = Hud.Tag(l.VerdictText, VerdictBrush(l.V)); DockPanel.SetDock(chip, Dock.Left); h.Children.Add(chip);
            bool tracked = l.Kind == "Startup" || l.Kind == "Task" || l.Kind == "Service" || l.Kind == "Extension";
            var id = tracked ? Snapshots.IdOf(l) : null;
            bool isNew = tracked && c.NewIds.Contains(id);
            if (isNew) { var nc = Hud.Tag("New since last week", Ui.Accent); DockPanel.SetDock(nc, Dock.Left); h.Children.Add(nc); }
            if (id != null) { var it = Hud.M("ID " + (id.Length > 12 ? id.Substring(id.Length - 12) : id), 10.5, Hud.Soft(Hud.Lilac, 0.9)); it.VerticalAlignment = VerticalAlignment.Center; it.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(it, Dock.Right); h.Children.Add(it); }
            var nm = OneLine(Ui.T(l.Name, 13.5, true)); nm.VerticalAlignment = VerticalAlignment.Center; h.Children.Add(nm);
            s.Children.Add(h);
            s.Children.Add(Ui.Muted(l.Reason, 12.5, 2));
            if (!string.IsNullOrEmpty(l.Detail)) s.Children.Add(Mono("> " + l.Detail, Hud.Muted));
            var result = Ui.T("", 12, false, Hud.Text); result.Visibility = Visibility.Collapsed; result.FontFamily = Hud.Mono;
            var btns = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            bool isFile = l.File != null && l.Exists && System.IO.File.Exists(l.File);
            if (l.File != null && l.Kind != "Hosts") btns.Children.Add(Ui.Btn("Open file location", () => Controller.OpenLocation(l.File)));
            if ((isFile || Snap.On) && l.Kind != "Extension" && l.Kind != "Hosts" && l.Exists)
            {
                btns.Children.Add(Ui.Btn("Scan with Defender", () => { var e = c.StartScan("custom", l.File); Say(e ?? "Scanning " + System.IO.Path.GetFileName(l.File) + " - see the Scan page."); }));
                btns.Children.Add(Ui.Btn("Look up on VirusTotal", () => { result.Visibility = Visibility.Visible; result.Text = "Looking up the file's fingerprint (SHA-256)..."; c.LookUp(l.File, m => result.Text = m); }));
            }
            if (Snap.On && c.SnapLookup != null && l.V == Verdict.Suspicious && l.Kind == "Startup") { result.Visibility = Visibility.Visible; result.Text = c.SnapLookup; }
            if (l.RunValue != null) btns.Children.Add(Ui.Btn("Disable", () =>
            {
                if (MessageBox.Show(this, "Stop \"" + l.Name + "\" from starting with Windows?\n\nHallow Guard moves the entry to its own backup, so you can put it back under \"Disabled by Hallow Guard\". The program itself isn't touched.", "Hallow Guard", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                var e = c.DisableStartup(l); Say(e ?? "\"" + l.Name + "\" won't start with Windows any more. Restore it below if you need it."); Show("leftovers");
            }, false, "Moves it out of your startup list into Hallow Guard's backup - Restore puts it back"));
            if (l.AdminKey != null) btns.Children.Add(Ui.Btn("Open Startup apps", () => c.RunFix("ms-settings:startupapps"), false, "This entry is for every user (changing it needs admin) - Windows' Startup apps page can switch it off"));
            if (btns.Children.Count > 0) s.Children.Add(btns);
            result.Margin = new Thickness(0, 6, 0, 0); s.Children.Add(result);
            var card = Card(s, 8);
            if (l.V == Verdict.Suspicious) PulseEdge(card, Hud.Red, true);
            else if (isNew) card.BorderBrush = Ui.Accent;
            return card;
        }

        // ---------------- Network: the connection map
        FrameworkElement NetMap(NetSnapshot n)
        {
            const double W = 720, H = 300, cx = 360, cy = 150, rx = 222, ry = 104;
            var cv = new Canvas { Width = W, Height = H };
            foreach (var k in new[] { 0.42, 0.72, 1.0 })
            {
                var e = new Ellipse { Width = 2 * rx * k, Height = 2 * ry * k, Stroke = Hud.Alpha(Hud.Lilac, k == 1.0 ? 0.22 : 0.12), StrokeThickness = 1, StrokeDashArray = new DoubleCollection { 2, 4 } };
                Canvas.SetLeft(e, cx - rx * k); Canvas.SetTop(e, cy - ry * k); cv.Children.Add(e);
            }
            var suspicious = new HashSet<string>(n.Listeners.Where(x => x.V == Verdict.Suspicious).Select(x => x.Name), StringComparer.OrdinalIgnoreCase);
            var apps = n.Apps.OrderByDescending(a => a.Remotes.Count + a.Lan).ThenBy(a => a.Name).Take(10).ToList();
            var nodes = new List<UIElement>(); var lines = new List<Line>();
            for (int i = 0; i < apps.Count; i++)
            {
                var a = apps[i];
                double ang = (-90 + 22 + i * 360.0 / Math.Max(apps.Count, 1)) * Math.PI / 180, x = cx + rx * Math.Cos(ang), y = cy + ry * Math.Sin(ang);
                bool bad = suspicious.Contains(a.Name); var col = bad ? Hud.Red : a.Remotes.Count > 0 ? Hud.Glow : Hud.Info;
                double r = 4 + Math.Min(5, a.Remotes.Count);
                var ln = new Line { X1 = cx, Y1 = cy, X2 = x, Y2 = y, Stroke = Hud.Alpha(col, bad ? 0.8 : 0.5), StrokeThickness = 1 + Math.Min(1.5, a.Remotes.Count / 3.0), StrokeDashArray = new DoubleCollection { 3, 3 } };
                lines.Add(ln); cv.Children.Add(ln);
                var dot = new Ellipse { Width = 2 * r, Height = 2 * r, Fill = Hud.Alpha(col, 0.25), Stroke = col, StrokeThickness = 1.5, Effect = Hud.Fx(new DropShadowEffect { Color = Hud.C(col), BlurRadius = 10, ShadowDepth = 0, Opacity = 0.9 }) };
                Canvas.SetLeft(dot, x - r); Canvas.SetTop(dot, y - r); nodes.Add(dot);
                var lab = new StackPanel { Width = 124 };
                lab.Children.Add(new TextBlock { Text = a.Name, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = bad ? Hud.Red : Hud.Text, TextTrimming = TextTrimming.CharacterEllipsis });
                var parts = new List<string>(); if (a.Remotes.Count > 0) parts.Add(a.Remotes.Count + (a.Remotes.Count == 1 ? " HOST" : " HOSTS")); if (a.Lan > 0) parts.Add(a.Lan + " LAN"); if (bad) parts.Add("SUSPICIOUS");
                lab.Children.Add(new TextBlock { Text = parts.Count == 0 ? "LOCAL" : string.Join(" \u00B7 ", parts), FontFamily = Hud.Mono, FontSize = 9.5, Foreground = col });
                double cos = Math.Cos(ang);
                if (cos > 0.3) { foreach (TextBlock tb in lab.Children) tb.TextAlignment = TextAlignment.Left; Canvas.SetLeft(lab, x + r + 7); Canvas.SetTop(lab, y - 15); }
                else if (cos < -0.3) { foreach (TextBlock tb in lab.Children) tb.TextAlignment = TextAlignment.Right; Canvas.SetLeft(lab, x - r - 7 - 124); Canvas.SetTop(lab, y - 15); }
                else { foreach (TextBlock tb in lab.Children) tb.TextAlignment = TextAlignment.Center; Canvas.SetLeft(lab, x - 62); Canvas.SetTop(lab, Math.Sin(ang) < 0 ? y - r - 32 : y + r + 3); }
                nodes.Add(lab);
                var lnRef = ln;
                Anim.Add(Hud.Animate(lnRef, Shape.StrokeDashOffsetProperty, () => Hud.Loop(0, -12, 1.4), 0));
            }
            foreach (var x in nodes) cv.Children.Add(x);
            // this PC: a hexagon in the middle with a slowly turning ring
            var ring = new Ellipse { Width = 84, Height = 84, Stroke = Hud.Alpha(Hud.Lilac, 0.6), StrokeThickness = 1.2, StrokeDashArray = new DoubleCollection { 6, 5 } };
            var rr = new RotateTransform(20, 42, 42); ring.RenderTransform = rr; Canvas.SetLeft(ring, cx - 42); Canvas.SetTop(ring, cy - 42); cv.Children.Add(ring);
            Anim.Add(Hud.Animate(rr, RotateTransform.AngleProperty, () => Hud.Loop(0, 360, 24), 20));
            var hexPts = new PointCollection(); for (int i = 0; i < 6; i++) { double a = (60 * i - 90) * Math.PI / 180; hexPts.Add(new Point(cx + 32 * Math.Cos(a), cy + 32 * Math.Sin(a))); }
            cv.Children.Add(new Polygon { Points = hexPts, Fill = Hud.Node, Stroke = Hud.Glow, StrokeThickness = 1.6, Effect = Hud.Fx(new DropShadowEffect { Color = Hud.C(Hud.Glow), BlurRadius = 16, ShadowDepth = 0, Opacity = 0.8 }) });
            var pc = Icons.Make("microchip", 18, Hud.Glow); Canvas.SetLeft(pc, cx - 9); Canvas.SetTop(pc, cy - 19); cv.Children.Add(pc);
            var me = new TextBlock { Text = "THIS PC", FontFamily = Hud.Mono, FontSize = 9.5, FontWeight = FontWeights.Bold, Foreground = Hud.Text, Width = 64, TextAlignment = TextAlignment.Center };
            Canvas.SetLeft(me, cx - 32); Canvas.SetTop(me, cy + 2); cv.Children.Add(me);
            var box = new StackPanel();
            var hd = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            var meta = Hud.M(n.Rows + " TABLE ENTRIES  //  READ " + Short(DateTime.Now - n.When).ToUpperInvariant() + " AGO", 10, Hud.Muted); meta.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(meta, Dock.Right); hd.Children.Add(meta);
            hd.Children.Add(Hud.Caps("Connection map", 12, Hud.Glow));
            box.Children.Add(hd);
            var vb = new Viewbox { Child = cv, Stretch = Stretch.Uniform, MaxHeight = 330, HorizontalAlignment = HorizontalAlignment.Center };
            box.Children.Add(vb);
            var legend = new WrapPanel { Margin = new Thickness(0, 4, 0, 0) };
            foreach (var lg in new[] { Tuple.Create(Hud.Glow, "INTERNET"), Tuple.Create(Hud.Info, "LOCAL NETWORK ONLY"), Tuple.Create(Hud.Red, "SUSPICIOUS (OPEN TO THE NETWORK)") })
            {
                var led = Hud.Led(lg.Item1, 6); led.Margin = new Thickness(-4, 0, 0, 0); legend.Children.Add(led);
                var lt = Hud.M(lg.Item2, 9.5, Hud.Muted); lt.Margin = new Thickness(0, 0, 16, 0); lt.VerticalAlignment = VerticalAlignment.Center; legend.Children.Add(lt);
            }
            if (n.Apps.Count > apps.Count) legend.Children.Add(Hud.M("+" + (n.Apps.Count - apps.Count) + " MORE IN THE LIST BELOW", 9.5, Hud.Muted));
            box.Children.Add(legend);
            AutomationProperties.SetName(cv, "Connection map: " + n.Apps.Count + " apps connected");
            return Card(box, 12);
        }

        // ---------------- Settings > Look (in both looks, so you can always switch back)
        FrameworkElement LookCard()
        {
            var s = new StackPanel();
            s.Children.Add(IconRow("microchip", Ui.Hi, "Look"));
            var row = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 8) };
            foreach (var lk in new[] { Look.ConsoleName, Look.ClassicName, Look.CyberBlueName })
            {
                var name = lk;
                row.Children.Add(Ui.Btn(Look.Label(name) + (name == Look.ConsoleName ? " (default)" : ""), () => { c.SetLook(name); Say("Look: " + Look.Label(name) + "."); }, Look.Current == name));
            }
            s.Children.Add(row);
            // v1.8: light or dark
            var mrow = new WrapPanel { Margin = new Thickness(0, 0, 0, 6) };
            var ml = Ui.T("Light or dark:", 12.5, true); ml.VerticalAlignment = VerticalAlignment.Center; ml.Margin = new Thickness(0, 0, 10, 0); mrow.Children.Add(ml);
            foreach (var md in new[] { Mode.Follow, Mode.Light, Mode.Dark })
            {
                var m = md;
                var mb = Ui.Btn(Mode.OwnLabel(m) + (m == Mode.Follow ? " (default)" : ""), () => { c.SetMode(m); Say("Light or dark: " + Mode.OwnLabel(m) + "."); }, Mode.Own(c.S.Mode) == m);
                mb.IsEnabled = !Look.IsCyberBlue; mrow.Children.Add(mb);
            }
            s.Children.Add(mrow);
            s.Children.Add(Ui.Muted("Now " + (Mode.IsLight ? "light" : "dark") + " (" + (Snap.On ? "picture" : Mode.Why(Look.Current, c.S.Mode, Accent.ReadMode())) + "). Follow Hallow uses the Light / Dark / Same as Windows switch in Hallow Toolkit's settings. Hallow console and Hallow classic come in light and dark; Cyber blue is always dark.", 11.5, 8));
            s.Children.Add(Ui.Muted("Hallow console is a security-console look in the Hallow colours: a radar score, a live scan console and a connection map, glowing in your Hallow accent. Hallow classic is the look from 1.3. Cyber blue is the console in the 1.4 neon cyan. Animations only run while this window is open and in front - they stop while it's minimized or in the tray, while a game or full-screen app runs, and when Windows' \"Show animations\" is off. Nothing else changes.", 11.5, Look.IsHud ? 4 : 0));
            if (Look.IsHud) s.Children.Add(Hud.M("ANIMATIONS: " + (Snap.On ? "RUN WHILE THE WINDOW IS IN FRONT" : Anim.Running ? "RUNNING" : "PAUSED (" + (Anim.Why ?? "-").ToUpperInvariant() + ")"), 10.5, Hud.Soft(Hud.Lilac, 0.95)));
            return Card(s);
        }
    }
}
