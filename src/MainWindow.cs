// Hallow Guard main window: the page list on the left (Overview, Scan, History, Network, Extensions, Ransomware, Hardening,
// Leftovers, Reports, Settings) and the open page. The v1.2 pages (Network, Extensions, Ransomware) are in Pages12.cs, the v1.6
// Hardening page in PagesHardening.cs.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using WF = System.Windows.Forms;

namespace HallowGuard
{
    public partial class MainWindow : Window
    {
        readonly Controller c;
        string page = "overview";
        readonly Dictionary<string, Button> nav = new Dictionary<string, Button>();
        Border content; TextBlock state, elapsed; Button updateBtn;
        bool showKnownGood;
        public bool Exiting;
        readonly DispatcherTimer tick;
        // v1.4: animations run only while this window is visible and focused, no game / full-screen app runs and Windows'
        // "Show animations" is on (see AnimGate in Look.cs)
        public readonly AnimGate Anim;
        int ticks;

        public MainWindow(Controller controller)
        {
            c = controller;
            Ui.Dress(this, "Hallow Guard", 1040);
            SizeToContent = SizeToContent.Manual; Height = 720; MinWidth = 900; MinHeight = 560;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            Anim = new AnimGate(new WindowView(this), c.BusySource, () => SystemParameters.ClientAreaAnimation) { Disabled = Snap.On };
            Rebuild();
            Action<string> changed = what => Dispatcher.BeginInvoke(new Action(() => OnChanged(what)));
            c.Changed += changed;
            tick = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            tick.Tick += (s, e) =>
            {
                if (elapsed != null && c.Scanning) elapsed.Text = ElapsedText();
                if (!IsVisible || WindowState == WindowState.Minimized) return;
                if (Look.IsHud) UpdateTelemetry();
                if (cyTick != null) cyTick();
                if (++ticks % 3 == 0) Anim.Update();
            };
            StateChanged += (s, e) => Anim.Update(); Activated += (s, e) => Anim.Update(); Deactivated += (s, e) => Anim.Update();
            IsVisibleChanged += (s, e) => Anim.Update();
            Closed += (s, e) => { c.Changed -= changed; tick.Stop(); Anim.Clear(); c.MainClosed(); };
            if (!Snap.On) tick.Start();
        }

        public void Rebuild()
        {
            Ui.Restyle(this);
            if (Look.IsHud) { CyRebuild(); return; }
            var root = new Grid();
            root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(224) });
            root.ColumnDefinitions.Add(new ColumnDefinition());
            // the page list
            var side = new DockPanel { Background = Ui.R("Panel"), LastChildFill = false };
            var head = new StackPanel { Margin = new Thickness(18, 18, 18, 16) };
            head.Children.Add(Ui.Header("GUARD", 19));
            head.Children.Add(Ui.Muted("Your safety center, powered by Microsoft Defender", 11.5, 0));
            DockPanel.SetDock(head, Dock.Top); side.Children.Add(head);
            nav.Clear();
            foreach (var p in new[] { Tuple.Create("overview", "Overview", "shield-halved"), Tuple.Create("scan", "Scan", "magnifying-glass"), Tuple.Create("history", "History", "clock-rotate-left"),
                Tuple.Create("network", "Network", "globe"), Tuple.Create("extensions", "Extensions", "puzzle-piece"), Tuple.Create("ransomware", "Ransomware", "lock"),
                Tuple.Create("hardening", "Hardening", "user-shield"), Tuple.Create("leftovers", "Leftovers", "broom"), Tuple.Create("reports", "Reports", "chart-line"), Tuple.Create("settings", "Settings", "gear") })
            {
                var id = p.Item1;
                var b = new Button { Style = Ui.S("Nav"), Content = Icons.WithText(p.Item3, p.Item2, 15, Ui.R("Text")), Margin = new Thickness(10, 0, 10, 0) };
                b.Click += (s, e) => Show(id);
                DockPanel.SetDock(b, Dock.Top); side.Children.Add(b); nav[id] = b;
            }
            var foot = new StackPanel { Margin = new Thickness(18, 0, 18, 16) };
            updateBtn = Ui.Btn("Update", () => c.InstallUpdate(), true); updateBtn.Visibility = c.PendingUpdate == null ? Visibility.Collapsed : Visibility.Visible; updateBtn.HorizontalAlignment = HorizontalAlignment.Left; updateBtn.Margin = new Thickness(0, 0, 0, 10);
            if (c.PendingUpdate != null) updateBtn.Content = "Update to v" + c.PendingUpdate.Version.ToString(2);
            foot.Children.Add(updateBtn);
            foot.Children.Add(Ui.Muted("Hallow Guard " + Program.Version + " uses Microsoft Defender's engine - it isn't an antivirus of its own.", 11, 0));
            DockPanel.SetDock(foot, Dock.Bottom); side.Children.Add(foot);
            root.Children.Add(side);
            // the page
            var right = new DockPanel(); Grid.SetColumn(right, 1);
            state = Ui.T("", 12, false, Ui.R("Muted")); state.Margin = new Thickness(28, 6, 28, 12); DockPanel.SetDock(state, Dock.Bottom); right.Children.Add(state);
            content = new Border(); right.Children.Add(content);
            root.Children.Add(right);
            Content = root;
            Show(page);
        }
        public void ShowUpdate(string label) { if (updateBtn != null) { updateBtn.Content = label; updateBtn.Visibility = Visibility.Visible; } }
        public void Say(string text) { if (state != null) state.Text = text; }

        void OnChanged(string what)
        {
            if (what == page || (what == "checks" && (page == "overview" || page == "ransomware" || page == "hardening")) ||(what == "scan" && (page == "scan" || page == "overview")) || (what == "threats" && page == "history") || (what == "reports" && page == "overview")) Show(page);
        }

        public void Show(string p)
        {
            page = p;
            foreach (var kv in nav) kv.Value.Tag = kv.Key == p ? "on" : null;
            elapsed = null; Anim.Clear(); cyTick = null;
            FrameworkElement el;
            switch (p)
            {
                case "scan": el = Look.IsHud ? CyScanPage() : ScanPage(); break;
                case "history": el = Look.IsHud ? CyHistoryPage() : HistoryPage(); break;
                case "leftovers": el = LeftoversPage(); break;
                case "network": el = NetworkPage(); break;
                case "extensions": el = ExtensionsPage(); break;
                case "ransomware": el = RansomwarePage(); break;
                case "hardening": el = HardeningPage(); break;
                case "reports": el = ReportsPage(); break;
                case "settings": el = SettingsPage(); break;
                default: page = "overview"; el = Look.IsHud ? CyOverviewPage() : OverviewPage(); break;
            }
            content.Child = new ScrollViewer { Content = el, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
            Anim.Update();
        }

        // ---------------- helpers
        static StackPanel Page(string title, string sub)
        {
            if (Look.IsHud) return CyPage(title, sub);
            var sp = new StackPanel { Margin = new Thickness(28, 22, 28, 12) };
            sp.Children.Add(new TextBlock { Text = title, FontSize = 22, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 4) });
            if (sub != null) sp.Children.Add(Ui.Muted(sub, 12.5, 14));
            return sp;
        }
        static Border Card(UIElement child, double bottom = 10)
        {
            if (Look.IsHud) return Hud.Card(child, new Thickness(16, 12, 16, 12), bottom);
            return new Border { Child = child, Background = Ui.R("Panel"), BorderBrush = Ui.R("Line"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(16, 12, 16, 12), Margin = new Thickness(0, 0, 0, bottom) };
        }
        static FrameworkElement Chip(string text, Brush color)
        {
            if (Look.IsHud) return Hud.Tag(text, color);
            var b = new Border { CornerRadius = new CornerRadius(9), Padding = new Thickness(8, 2, 8, 2), Background = color, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
            b.Child = new TextBlock { Text = text, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = Ui.OnStatus };
            return b;
        }
        static Brush StateBrush(CheckState s) { return s == CheckState.Good ? Ui.Green : s == CheckState.Warn ? Ui.Amber : s == CheckState.Bad ? Ui.Red : s == CheckState.Info ? Ui.Info : Ui.R("Muted"); }
        static string StateIcon(CheckState s) { return s == CheckState.Good ? "circle-check" : s == CheckState.Warn ? "triangle-exclamation" : s == CheckState.Bad ? "circle-xmark" : s == CheckState.Info ? "circle-info" : "circle-question"; }
        static Brush ScoreBrush(int s) { return s >= 90 ? Ui.Green : s >= 70 ? Ui.Amber : Ui.Red; }
        static Brush VerdictBrush(Verdict v) { return v == Verdict.KnownGood ? Ui.Green : v == Verdict.Suspicious ? Ui.Red : Ui.Amber; }
        static string When(DateTime? t) { return t == null ? "unknown" : t.Value.ToString("d MMM yyyy, HH:mm"); }
        static DateTime? Iso(string s) { DateTime t; return DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out t) ? t : (DateTime?)null; }
        static TextBlock Mono(string text, Brush fg)
        {
            return new TextBlock { Text = text, FontFamily = Look.IsHud ? Hud.Mono : new FontFamily("Consolas"), FontSize = 11.5, Foreground = fg, TextTrimming = TextTrimming.CharacterEllipsis, Margin = new Thickness(0, 0, 0, 2) };
        }
        static TextBlock OneLine(TextBlock t) { t.TextWrapping = TextWrapping.NoWrap; t.TextTrimming = TextTrimming.CharacterEllipsis; return t; }

        // the score ring: a grey circle with the coloured part drawn as an arc
        static FrameworkElement Ring(int score, double size)
        {
            var g = new Grid { Width = size, Height = size };
            double th = 12, r = (size - th) / 2, cx = size / 2, cy = size / 2;
            g.Children.Add(new Ellipse { Stroke = Ui.R("Line"), StrokeThickness = th, Margin = new Thickness(th / 2) });
            if (score >= 100) g.Children.Add(new Ellipse { Stroke = ScoreBrush(score), StrokeThickness = th, Margin = new Thickness(th / 2) });
            else if (score > 0)
            {
                double a = score / 100.0 * 2 * Math.PI;
                var fig = new PathFigure { StartPoint = new Point(cx, cy - r) };
                fig.Segments.Add(new ArcSegment(new Point(cx + r * Math.Sin(a), cy - r * Math.Cos(a)), new Size(r, r), 0, score > 50, SweepDirection.Clockwise, true));
                var geo = new PathGeometry(); geo.Figures.Add(fig);
                g.Children.Add(new System.Windows.Shapes.Path { Data = geo, Stroke = ScoreBrush(score), StrokeThickness = th, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round });
            }
            var mid = new StackPanel { VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center };
            mid.Children.Add(new TextBlock { Text = score < 0 ? "..." : score.ToString(), FontSize = size * 0.3, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center });
            mid.Children.Add(new TextBlock { Text = "of 100", FontSize = 11.5, Foreground = Ui.R("Muted"), HorizontalAlignment = HorizontalAlignment.Center });
            g.Children.Add(mid);
            return g;
        }

        // ---------------- Overview (v1.1: one family score - the Windows checks and the Hallow apps - with one to-do list)
        FrameworkElement OverviewPage()
        {
            var sp = Page("Overview", null);
            int score = c.FamilyValue >= 0 ? c.FamilyValue : c.ScoreValue;
            var top = new DockPanel { Margin = new Thickness(0, 4, 0, 16) };
            var ring = Ring(score, 150); ring.Margin = new Thickness(0, 0, 24, 0); DockPanel.SetDock(ring, Dock.Left); top.Children.Add(ring);
            var info = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            info.Children.Add(Ui.T(score < 0 ? "Checking your PC..." : Score.Label(score), 24, true, score < 0 ? null : ScoreBrush(score), 4));
            var todo = c.Todo();
            info.Children.Add(Ui.Muted(c.Checks == null ? "Reading Windows Security, system settings and your Hallow apps - nothing is changed." : (todo.Count == 0 ? "Everything Hallow Guard checks is in good shape." : "One score for the whole PC: Windows, your Hallow apps, the network and your browsers.") + (c.CheckedAt == null ? "" : "  Checked " + Score.Ago(c.CheckedAt, DateTime.Now) + "."), 12.5, 8));
            if (c.ScoreValue >= 0)
            {
                var chips = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
                chips.Children.Add(GroupChip("Windows", c.ScoreValue));
                chips.Children.Add(GroupChip("Hallow apps", c.AppsValue));
                chips.Children.Add(GroupChip("Network & browsers", c.MoreValue));
                chips.Children.Add(GroupChip("Hardening", c.HardValue));
                info.Children.Add(chips);
            }
            var again = Ui.Btn(c.Checking ? "Checking..." : "Check again", () => c.RefreshChecks()); again.IsEnabled = !c.Checking;
            var quick = Ui.Btn(c.Scanning ? "Scanning..." : "Quick scan", () => { var e = c.StartScan("quick", null); if (e != null) Say(e); else Show("scan"); }, true); quick.IsEnabled = !c.Scanning;
            info.Children.Add(Ui.Row(quick, again));
            top.Children.Add(info);
            sp.Children.Add(top);
            // the one to-do list
            if (c.Checks != null)
            {
                sp.Children.Add(Section("To do", todo.Count == 0 ? "nothing to fix" : "the " + (todo.Count == 1 ? "thing" : todo.Count + " things") + " worth the most points first"));
                if (todo.Count == 0) sp.Children.Add(Card(Ui.T("Nothing to fix right now.", 13, false, Ui.Green), 8));
                int i = 0;
                foreach (var ch in todo)
                {
                    i++; var row = new DockPanel();
                    var num = new Border { Width = 26, Height = 26, CornerRadius = new CornerRadius(13), Background = StateBrush(ch.State), Margin = new Thickness(0, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center };
                    num.Child = new TextBlock { Text = i.ToString(), FontWeight = FontWeights.Bold, Foreground = Ui.OnStatus, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                    DockPanel.SetDock(num, Dock.Left); row.Children.Add(num);
                    var fb = FixButton(ch, true); DockPanel.SetDock(fb, Dock.Right); row.Children.Add(fb);
                    var txt = new StackPanel();
                    txt.Children.Add(Ui.T(ch.Title + (ch.Penalty > 0 ? "   +" + ch.Penalty + (ch.Penalty == 1 ? " point" : " points") : ""), 13.5, true, null, 2));
                    txt.Children.Add(Ui.Muted(ch.Line, 12));
                    row.Children.Add(txt);
                    sp.Children.Add(Card(row, 8));
                }
            }
            // the two groups
            if (c.Checks != null)
            {
                sp.Children.Add(Section("Windows", c.ScoreValue + " of 100"));
                foreach (var ch in Ordered(c.Checks)) sp.Children.Add(CheckCard(ch));
            }
            if (c.AppChecks != null)
            {
                sp.Children.Add(Section("Hallow apps", c.AppsValue == null ? "none installed - each one is optional" : c.AppsValue + " of 100"));
                foreach (var ch in c.AppChecks.OrderBy(x => x.NotInstalled ? 1 : 0).ThenBy(x => Rank(x.State))) sp.Children.Add(CheckCard(ch));
                sp.Children.Add(Ui.Muted("Hallow apps that aren't installed never cost points. Installed ones can take off a few: Hallow Keys up to " + FamilyScore.KeysMax + " (counts only - Guard never opens your vault), Hallow Vault up to " + FamilyScore.VaultMax + ", Hallow Shield 2; the family score is the Windows score minus those points (at most " + FamilyScore.AppsCap + ").", 11.5, 8));
            }
            if (c.MoreChecks != null)
            {
                sp.Children.Add(Section("Network & browsers", c.MoreValue + " of 100"));
                foreach (var ch in Ordered(c.MoreChecks)) sp.Children.Add(CheckCard(ch));
                sp.Children.Add(Ui.Muted("A suspicious program open to the network costs " + NetView.SuspiciousPoints + " points, each high-risk browser extension " + ExtScan.HighPoints + " (at most " + ExtScan.MaxPoints + "); this group takes at most " + MoreScore.Cap + " off the family score.", 11.5, 8));
            }
            HardeningSummary(sp);
            sp.Children.Add(Ui.Muted("Hallow Guard only reads these. \"Open settings\" takes you to the right Windows page; nothing is changed behind your back.", 11.5, 0));
            return sp;
        }
        static FrameworkElement SubHead(string text) { return Look.IsHud ? Section(text, null) : Ui.T(text, 14, true, null, 6); }
        static int Rank(CheckState s) { return s == CheckState.Bad ? 0 : s == CheckState.Warn ? 1 : s == CheckState.Unknown ? 2 : s == CheckState.Info ? 3 : 4; }
        static IEnumerable<Check> Ordered(IEnumerable<Check> l) { return l.OrderBy(x => Rank(x.State)); }
        static FrameworkElement Section(string title, string sub)
        {
            if (Look.IsHud) return CySection(title, sub);
            var p = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 10, 0, 8) };
            p.Children.Add(new TextBlock { Text = title, FontSize = 16, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Bottom });
            if (sub != null) p.Children.Add(new TextBlock { Text = "   " + sub, FontSize = 12, Foreground = Ui.R("Muted"), VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(0, 0, 0, 2) });
            return p;
        }
        static FrameworkElement GroupChip(string name, int? score)
        {
            var b = new Border { CornerRadius = new CornerRadius(10), Padding = new Thickness(10, 3, 10, 3), Background = Ui.R("Panel"), BorderBrush = Ui.R("Line"), BorderThickness = new Thickness(1), Margin = new Thickness(0, 0, 8, 0) };
            var t = new TextBlock { FontSize = 12 };
            t.Inlines.Add(new System.Windows.Documents.Run(name + "  ") { Foreground = Ui.R("Muted") });
            t.Inlines.Add(new System.Windows.Documents.Run(score == null ? "-" : score.ToString()) { FontWeight = FontWeights.Bold, Foreground = score == null ? Ui.R("Muted") : ScoreBrush(score.Value) });
            b.Child = t; return b;
        }
        Button FixButton(Check ch, bool accent)
        {
            var act = ch.FixAction; var fb = Ui.Btn(ch.FixLabel, () => c.RunFix(act), accent); fb.Margin = new Thickness(12, 0, 0, 0); fb.VerticalAlignment = VerticalAlignment.Center;
            fb.ToolTip = act.StartsWith("admin:") ? "Windows asks for admin first. It only reads the setting." : act.StartsWith("scan:") || act == "page:scan" ? "Asks Microsoft Defender to scan."
                : act.StartsWith("page:") ? "Opens Hallow Guard's page about it - nothing is changed."
                : act.StartsWith("url:") ? "Opens the app's page on GitHub in your browser." : act.StartsWith("app:") ? "Opens the Hallow app - Hallow Guard doesn't change anything in it." : "Opens the right Windows page - Hallow Guard doesn't change it for you.";
            return fb;
        }
        FrameworkElement CheckCard(Check ch)
        {
            var row = new DockPanel();
            var ic = Icons.Make(ch.NotInstalled ? "puzzle-piece" : StateIcon(ch.State), 20, ch.NotInstalled ? Ui.R("Muted") : StateBrush(ch.State)); ic.Margin = new Thickness(0, 2, 14, 0); ic.VerticalAlignment = VerticalAlignment.Top; DockPanel.SetDock(ic, Dock.Left); row.Children.Add(ic);
            if (ch.FixLabel != null) { var fb = FixButton(ch, false); DockPanel.SetDock(fb, Dock.Right); row.Children.Add(fb); }
            var txt = new StackPanel();
            var head = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 2) };
            if (ch.Group == HardScore.Group) { var code = new TextBlock { Text = Hud.Code(ch.State), FontFamily = new FontFamily("Consolas"), FontSize = 12, FontWeight = FontWeights.Bold, Foreground = StateBrush(ch.State), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) }; head.Children.Add(code); }   // v1.6: a status code, never colour alone
            head.Children.Add(Ui.T(ch.Title, 13.5, true));
            if (ch.NotInstalled) { var chip = Chip("Not installed", Ui.R("Line")); ((TextBlock)((Border)chip).Child).Foreground = Ui.R("Muted"); chip.Margin = new Thickness(10, 0, 0, 0); head.Children.Add(chip); }
            txt.Children.Add(head);
            txt.Children.Add(Ui.Muted(ch.NotInstalled && ch.Line.StartsWith("Not installed. ") ? ch.Line.Substring(15) : ch.Line, 12.5));
            row.Children.Add(txt);
            return Card(row, 8);
        }
        // ---------------- Scan
        string ElapsedText()
        {
            var j = c.Current; if (j == null) return "";
            var e = j.Elapsed;
            var t = e.TotalHours >= 1 ? ((int)e.TotalHours) + ":" + e.Minutes.ToString("00") + ":" + e.Seconds.ToString("00") : e.Minutes + ":" + e.Seconds.ToString("00");
            return "Running for " + t + (j.Kind == "full" ? " - a full scan can take an hour or more." : j.Kind == "quick" ? " - usually a few minutes." : "");
        }
        FrameworkElement ScanPage()
        {
            var sp = Page("Scan", "Microsoft Defender does the scanning - Hallow Guard asks it to and shows you the result. You can keep using the PC while it runs.");
            var grid = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            for (int i = 0; i < 3; i++) { grid.ColumnDefinitions.Add(new ColumnDefinition()); if (i < 2) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(10) }); }
            Func<string, string, string, Button, FrameworkElement> tile = (icon, title, text, btn) =>
            {
                var s = new StackPanel();
                var h = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
                var ic = Icons.Make(icon, 18, Ui.Accent); ic.Margin = new Thickness(0, 0, 9, 0); h.Children.Add(ic); h.Children.Add(Ui.T(title, 14.5, true));
                s.Children.Add(h); s.Children.Add(Ui.Muted(text, 12, 10)); btn.HorizontalAlignment = HorizontalAlignment.Left; s.Children.Add(btn);
                return Card(s, 0);
            };
            bool busy = c.Scanning;
            var q = Ui.Btn("Quick scan", () => Start("quick", null), true); q.IsEnabled = !busy;
            var f = Ui.Btn("Full scan", () => Start("full", null)); f.IsEnabled = !busy;
            var fo = Ui.Btn("Choose a folder", PickFolder); fo.IsEnabled = !busy;
            var t1 = tile("bolt", "Quick scan", "The places malware usually hides. A few minutes.", q);
            var t2 = tile("hard-drive", "Full scan", "Every file on every drive. Can take an hour or more.", f); Grid.SetColumn(t2, 2);
            var t3 = tile("folder-open", "A folder", "Just the folder you pick, like a USB stick.", fo); Grid.SetColumn(t3, 4);
            grid.Children.Add(t1); grid.Children.Add(t2); grid.Children.Add(t3);
            sp.Children.Add(grid);
            // drop target
            var drop = new Grid { Margin = new Thickness(0, 0, 0, 10), MinHeight = 74, AllowDrop = true, Background = Brushes.Transparent };
            drop.Children.Add(new Rectangle { Stroke = Ui.R("Line"), StrokeThickness = 1.5, StrokeDashArray = new DoubleCollection { 5, 4 }, RadiusX = 12, RadiusY = 12 });
            var dropRow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            var dic = Icons.Make("file-shield", 22, Ui.R("Muted")); dic.Margin = new Thickness(0, 0, 12, 0); dropRow.Children.Add(dic);
            var dt = Ui.T("Drop a file here to scan it", 13.5, false, Ui.R("Muted")); dt.VerticalAlignment = VerticalAlignment.Center; dropRow.Children.Add(dt);
            var pick = Ui.Btn("Choose a file", PickFile); pick.Margin = new Thickness(14, 0, 0, 0); pick.IsEnabled = !busy; dropRow.Children.Add(pick);
            drop.Children.Add(dropRow);
            drop.DragOver += (s, e) => { e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) && !c.Scanning ? DragDropEffects.Copy : DragDropEffects.None; e.Handled = true; };
            drop.Drop += (s, e) => { var files = e.Data.GetData(DataFormats.FileDrop) as string[]; if (files != null && files.Length > 0) Start("custom", files[0]); };
            sp.Children.Add(drop);
            // progress or the last result
            if (busy)
            {
                var j = c.Current; var p = new StackPanel();
                var what = j.Kind == "quick" ? "Quick scan running..." : j.Kind == "full" ? "Full scan running..." : j.Kind == "download" ? "Checking a new download: " + System.IO.Path.GetFileName(j.Target) : "Scanning " + j.Target;
                var hdr = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
                var cancel = Ui.Btn("Cancel", () => { c.CancelScan(); Say("Cancelling..."); }); DockPanel.SetDock(cancel, Dock.Right); hdr.Children.Add(cancel);
                var wt = OneLine(Ui.T(what, 14, true)); wt.VerticalAlignment = VerticalAlignment.Center; hdr.Children.Add(wt);
                p.Children.Add(hdr);
                p.Children.Add(new ProgressBar { IsIndeterminate = !Snap.On, Value = Snap.On ? 38 : 0, Margin = new Thickness(0, 0, 0, 8) });
                elapsed = Ui.Muted(ElapsedText(), 12); p.Children.Add(elapsed);
                sp.Children.Add(Card(p));
            }
            else if (c.LastScanMessage != null)
            {
                var good = c.LastScanMessage.Contains("nothing found");
                var row = new DockPanel();
                var ic = Icons.Make(good ? "circle-check" : c.LastScanMessage.Contains("found") ? "triangle-exclamation" : "circle-info", 18, good ? Ui.Green : Ui.Amber); ic.Margin = new Thickness(0, 0, 12, 0); DockPanel.SetDock(ic, Dock.Left); row.Children.Add(ic);
                row.Children.Add(Ui.T(c.LastScanMessage, 13));
                sp.Children.Add(Card(row));
            }
            // Watch Downloads
            var w = new StackPanel();
            w.Children.Add(Ui.Switch("Watch Downloads - scan each new download as soon as it has finished", c.S.WatchDownloads, v => c.SetWatch(v)));
            var where = Snap.On ? @"C:\Users\Alex\Downloads" : DownloadWatcher.DownloadsFolder();
            w.Children.Add(Ui.Muted("Off by default. Hallow Guard waits until a file stops growing (and skips .crdownload / .part files), then asks Defender to check just that file. You only hear from it if something is found. Folder: " + where, 11.5, 4));
            List<string> wl; lock (c.WatchLog) wl = c.WatchLog.ToList();
            foreach (var l in wl.Take(5)) w.Children.Add(Mono(l, l.Contains("THREAT") ? Ui.Red : Ui.R("Muted")));
            sp.Children.Add(Card(w));
            // recent scans
            List<ScanRecord> scans; lock (c.S.Scans) scans = c.S.Scans.Take(8).ToList();
            if (scans.Count > 0)
            {
                sp.Children.Add(Ui.T("Recent scans by Hallow Guard", 14, true, null, 6));
                foreach (var r in scans)
                {
                    var row = new DockPanel { Margin = new Thickness(2, 0, 0, 5) };
                    var res = Ui.T(r.Result == "clean" ? "nothing found" : r.Result == "threats" ? r.Threats + " found" : r.Result, 12, true, r.Result == "clean" ? Ui.Green : r.Result == "threats" ? Ui.Red : Ui.R("Muted"));
                    res.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(res, Dock.Right); row.Children.Add(res);
                    var kind = r.Kind == "quick" ? "Quick scan" : r.Kind == "full" ? "Full scan" : r.Kind == "download" ? "Download: " + System.IO.Path.GetFileName(r.Target) : "Folder/file: " + r.Target;
                    row.Children.Add(OneLine(Ui.T(When(Iso(r.End)) + "   " + kind, 12)));
                    sp.Children.Add(row);
                }
            }
            return sp;
        }
        void Start(string kind, string target) { var e = c.StartScan(kind, target); if (e != null) Say(e); }
        void PickFolder()
        {
            using (var d = new WF.FolderBrowserDialog { Description = "Pick a folder for Microsoft Defender to scan", ShowNewFolderButton = false })
                if (d.ShowDialog() == WF.DialogResult.OK) Start("custom", d.SelectedPath);
        }
        void PickFile()
        {
            var d = new Microsoft.Win32.OpenFileDialog { Title = "Pick a file for Microsoft Defender to scan" };
            if (d.ShowDialog(this) == true) Start("custom", d.FileName);
        }

        // ---------------- History
        FrameworkElement HistoryPage()
        {
            var sp = Page("History", "What Microsoft Defender has found on this PC, in plain words. To restore or remove something, use Windows Security.");
            var top = Ui.Row(Ui.Btn("Open in Windows Security", () => c.RunFix("windowsdefender://history")), Ui.Btn(c.ThreatsLoading ? "Loading..." : "Refresh", () => c.RefreshThreats()));
            top.Margin = new Thickness(0, 0, 0, 12); sp.Children.Add(top);
            if (c.ThreatError != null) sp.Children.Add(Card(Ui.T(c.ThreatError, 12.5, false, Ui.Amber)));
            else if (c.ThreatList == null) sp.Children.Add(Ui.Muted("Reading Defender's history...", 12.5));
            else if (c.ThreatList.Count == 0)
            {
                var row = new StackPanel { Orientation = Orientation.Horizontal };
                var ic = Icons.Make("circle-check", 18, Ui.Green); ic.Margin = new Thickness(0, 0, 10, 0); row.Children.Add(ic);
                row.Children.Add(Ui.T("Defender hasn't found anything on this PC.", 13));
                sp.Children.Add(Card(row));
            }
            else foreach (var t in c.ThreatList)
                {
                    var s = new StackPanel();
                    var h = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
                    var sev = Chip(t.SeverityText, t.Severity >= 4 ? Ui.Red : t.Severity == 2 ? Ui.Amber : t.Severity == 1 ? Ui.Low : Ui.R("Muted")); DockPanel.SetDock(sev, Dock.Left); h.Children.Add(sev);
                    var when = Ui.Muted(When(t.When), 11.5); when.VerticalAlignment = VerticalAlignment.Center; when.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(when, Dock.Right); h.Children.Add(when);
                    var nm = OneLine(Ui.T(t.Kind + "  -  " + t.Name, 13.5, true)); nm.VerticalAlignment = VerticalAlignment.Center; h.Children.Add(nm);
                    s.Children.Add(h);
                    s.Children.Add(Ui.T(t.What, 12.5, false, null, 3));
                    var bad = t.Action.Contains("couldn't") || t.Action.Contains("waiting") || t.StatusId == 5;
                    s.Children.Add(Ui.T(t.Action, 12.5, false, bad ? Ui.Amber : Ui.Green, 3));
                    foreach (var p in t.Paths.Take(3)) s.Children.Add(Mono(p, Ui.R("Muted")));
                    var first = t.Paths.FirstOrDefault();
                    var btns = Ui.Row(Ui.Btn("Open in Windows Security", () => c.RunFix("windowsdefender://history")));
                    if (first != null && first.Contains(":\\")) btns.Children.Add(Ui.Btn("Open file location", () => Controller.OpenLocation(first)));
                    btns.Margin = new Thickness(0, 8, 0, 0); s.Children.Add(btns);
                    sp.Children.Add(Card(s));
                }
            return sp;
        }

        // ---------------- Leftovers (v1.3: what changed since last week is in Pages13.cs)
        static readonly string[][] Groups = {
            new[] { "Startup", "Starts with Windows" }, new[] { "Task", "Scheduled tasks (not Microsoft's)" }, new[] { "Service", "Services (not Microsoft's)" },
            new[] { "Process", "Running unsigned from Temp, AppData or Downloads" }, new[] { "Extension", "Browser extensions" }, new[] { "Hosts", "Hosts file entries" } };
        FrameworkElement LeftoversPage()
        {
            var sp = Page("Leftovers", "A one-click look at what starts with Windows, runs in the background or sits in your browsers - and whether it's known. Nothing is deleted; Disable only moves a startup entry aside so it can be put back.");
            var top = new WrapPanel { Margin = new Thickness(0, 0, 0, 10) };
            var run = Ui.Btn(c.Hunting ? "Looking..." : c.LeftoverList == null ? "Start the hunt" : "Look again", () => c.Hunt(), true); run.IsEnabled = !c.Hunting; top.Children.Add(run);
            var sw = Ui.Switch("Show known good", showKnownGood, v => { showKnownGood = v; Show("leftovers"); }); sw.Margin = new Thickness(8, 0, 0, 0); sw.VerticalAlignment = VerticalAlignment.Center; top.Children.Add(sw);
            sp.Children.Add(top);
            if (c.Hunting)
            {
                var p = new StackPanel(); p.Children.Add(Ui.T("Looking at: " + c.HuntStep, 13, false, null, 8)); p.Children.Add(new ProgressBar { IsIndeterminate = !Snap.On, Value = 50 }); sp.Children.Add(Card(p));
            }
            if (c.LeftoverList == null && c.Changes != null) sp.Children.Add(ChangesCard());
            if (c.LeftoverList != null)
            {
                var all = c.LeftoverList;
                var sum = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
                sum.Children.Add(Chip(all.Count(x => x.V == Verdict.Suspicious) + " suspicious", Ui.Red)); sum.Children.Add(Chip(all.Count(x => x.V == Verdict.Unknown) + " unknown", Ui.Amber)); sum.Children.Add(Chip(all.Count(x => x.V == Verdict.KnownGood) + " known good", Ui.Green));
                if (c.HuntedAt != null) { var ht = Ui.Muted("Checked " + Score.Ago(c.HuntedAt, DateTime.Now) + ".", 11.5); ht.VerticalAlignment = VerticalAlignment.Center; sum.Children.Add(ht); }
                sp.Children.Add(sum);
                if (c.Changes != null || c.HuntedAt != null) sp.Children.Add(ChangesCard());
                foreach (var g in Groups)
                {
                    var kind = g[0];
                    var items = all.Where(x => x.Kind == kind && (showKnownGood || x.V != Verdict.KnownGood)).OrderBy(x => x.V == Verdict.Suspicious ? 0 : x.V == Verdict.Unknown ? 1 : 2).ThenBy(x => x.Name).ToList();
                    int hidden = all.Count(x => x.Kind == kind && x.V == Verdict.KnownGood && !showKnownGood);
                    if (items.Count == 0 && hidden == 0) continue;
                    sp.Children.Add(SubHead(g[1]));
                    foreach (var l in items) sp.Children.Add(LeftoverRow(l));
                    if (hidden > 0) sp.Children.Add(Ui.Muted(hidden + " known good " + (hidden == 1 ? "item" : "items") + " hidden.", 11.5, 10));
                }
            }
            var disabled = c.Store.List();
            if (disabled.Count > 0)
            {
                sp.Children.Add(SubHead("Disabled by Hallow Guard"));
                foreach (var d in disabled)
                {
                    var id = d.Id; var row = new DockPanel();
                    var rb = Ui.Btn("Restore", () => { var e = c.RestoreStartup(id); Say(e ?? "Put back - it starts with Windows again."); Show("leftovers"); }); DockPanel.SetDock(rb, Dock.Right); row.Children.Add(rb);
                    var tx = new StackPanel(); tx.Children.Add(Ui.T(d.Name, 13, true)); tx.Children.Add(OneLine(Ui.Muted(d.Data + "  -  disabled " + When(Iso(d.When)), 11.5))); row.Children.Add(tx);
                    sp.Children.Add(Card(row, 6));
                }
            }
            return sp;
        }
        FrameworkElement LeftoverRow(Leftover l)
        {
            if (Look.IsHud) return CyLeftoverRow(l);
            var s = new StackPanel();
            var h = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
            var chip = Chip(l.VerdictText, VerdictBrush(l.V)); DockPanel.SetDock(chip, Dock.Left); h.Children.Add(chip);
            bool isNew = (l.Kind == "Startup" || l.Kind == "Task" || l.Kind == "Service" || l.Kind == "Extension") && c.NewIds.Contains(Snapshots.IdOf(l));
            if (isNew) { var nc = Chip("New since last week", Ui.Accent); DockPanel.SetDock(nc, Dock.Left); h.Children.Add(nc); }
            var nm = OneLine(Ui.T(l.Name, 13.5, true)); nm.VerticalAlignment = VerticalAlignment.Center; h.Children.Add(nm);
            s.Children.Add(h);
            s.Children.Add(Ui.Muted(l.Reason, 12.5, 2));
            if (!string.IsNullOrEmpty(l.Detail)) s.Children.Add(Mono(l.Detail, Ui.R("Muted")));
            var result = Ui.T("", 12, false, Ui.R("Text")); result.Visibility = Visibility.Collapsed;
            var btns = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            bool isFile = l.File != null && l.Exists && File.Exists(l.File);
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
            var card = Card(s, 8); if (isNew) { card.BorderBrush = Ui.Accent; card.BorderThickness = new Thickness(1.5); }
            return card;
        }

        // ---------------- Settings
        FrameworkElement SettingsPage()
        {
            var sp = Page("Settings", null);
            sp.Children.Add(LookCard());
            var a = new StackPanel();
            a.Children.Add(Ui.Switch("Watch Downloads - scan new downloads once they've finished (off by default)", c.S.WatchDownloads, v => c.SetWatch(v)));
            a.Children.Add(Ui.Switch("Start with Windows (in the tray, off by default) - needed for Watch Downloads, the scan while you're away, the weekly report and the reminder", c.StartsWithWindows(), v => { c.SetStartWithWindows(v); c.WriteStatus(); }));
            a.Children.Add(Ui.Switch("Remind me when nothing was scanned for a week", c.S.WeeklyReminder, v => { c.S.WeeklyReminder = v; c.S.Save(); c.WriteStatus(); }));
            a.Children.Add(Ui.Switch("Use the Hallow icon (when Hallow Hub runs, notifications come from its icon)", c.S.UseHallowIcon, v => { c.S.UseHallowIcon = v; c.S.Save(); c.CheckHost(); }));
            a.Children.Add(Ui.Switch("Use the Hallow accent (the colour picked in Hallow Toolkit)", c.S.UseHallowAccent, v => { c.S.UseHallowAccent = v; c.S.Save(); c.ApplyAccent(); }));
            sp.Children.Add(Card(a));
            sp.Children.Add(AwayCard());
            // VirusTotal
            var vt = new StackPanel();
            var vh = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
            var vic = Icons.Make("fingerprint", 17, Ui.Hi); vic.Margin = new Thickness(0, 0, 9, 0); vh.Children.Add(vic); vh.Children.Add(Ui.T("VirusTotal second opinion (optional)", 14, true));
            vt.Children.Add(vh);
            vt.Children.Add(Ui.Muted("With your own free VirusTotal API key, \"Look up\" asks VirusTotal about a file by its fingerprint (SHA-256) only - the file is never uploaded. Without a key, Look up opens the file's VirusTotal page in your browser. The key is kept encrypted for your Windows account.", 12, 10));
            var msg = Ui.Muted("", 11.5, 0);
            if (c.S.VtKey != null)
            {
                var ok = Ui.T("A key is saved.", 12.5, false, Ui.Green); ok.VerticalAlignment = VerticalAlignment.Center; ok.Margin = new Thickness(0, 0, 12, 0);
                vt.Children.Add(Ui.Row(ok, Ui.Btn("Remove key", () => { c.S.SetVtKey(null); c.S.Save(); c.WriteStatus(); Show("settings"); Say("VirusTotal key removed."); })));
            }
            else
            {
                var box = Ui.PasswordField(); box.Margin = new Thickness(0, 0, 8, 0);
                var row = new DockPanel();
                var save = Ui.Btn("Save key", () =>
                {
                    var k = box.Password.Trim();
                    if (!System.Text.RegularExpressions.Regex.IsMatch(k, "^[0-9a-fA-F]{64}$")) { msg.Text = "A VirusTotal API key is 64 characters (0-9, a-f). Copy it from your VirusTotal profile > API key."; msg.Foreground = Ui.Amber; return; }
                    c.S.SetVtKey(k); c.S.Save(); c.WriteStatus(); box.Clear(); Show("settings"); Say("VirusTotal key saved (encrypted).");
                }, true);
                save.Margin = new Thickness(0); DockPanel.SetDock(save, Dock.Right); row.Children.Add(save); row.Children.Add(box);
                vt.Children.Add(row);
                var get = Ui.Btn("Get a free key", () => { if (GuardSettings.TestDir == null) try { System.Diagnostics.Process.Start("https://www.virustotal.com/gui/join-us"); } catch { } });
                get.HorizontalAlignment = HorizontalAlignment.Left; get.Margin = new Thickness(0, 8, 0, 0); vt.Children.Add(get);
            }
            msg.Margin = new Thickness(0, 6, 0, 0); vt.Children.Add(msg);
            sp.Children.Add(Card(vt));
            var b = Ui.Row(Ui.Btn("Check for updates", () => c.CheckForUpdate(true)), Ui.Btn("Open data folder", () => { try { Directory.CreateDirectory(GuardSettings.Dir); System.Diagnostics.Process.Start("explorer.exe", "\"" + GuardSettings.Dir + "\""); } catch { } }), Ui.Btn("Windows Security", () => c.RunFix("windowsdefender://threat")));
            b.Margin = new Thickness(0, 4, 0, 12); sp.Children.Add(b);
            sp.Children.Add(Ui.Muted("Hallow Guard " + Program.Version + " is a friendly view on top of Microsoft Defender. It uses Defender's engine for every scan; it isn't an antivirus of its own and never switches Defender off, replaces it or changes its settings. Nothing is sent anywhere except a file's fingerprint to VirusTotal, when you ask for it with your own key.", 11.5, 6));
            sp.Children.Add(Ui.Muted("Icons: Font Awesome Free (CC BY 4.0).", 11, 0));
            return sp;
        }
    }

    public static class CrashNotice
    {
        public static Window Make(string file)
        {
            var w = new Window(); Ui.Dress(w, "Hallow Guard", 440);
            w.ResizeMode = ResizeMode.NoResize; w.WindowStartupLocation = WindowStartupLocation.CenterScreen; w.Topmost = true;
            var sp = new StackPanel { Margin = new Thickness(22, 18, 22, 18) };
            sp.Children.Add(Ui.T("Hallow Guard closed unexpectedly last time", 15, true, null, 6));
            DateTime when = DateTime.Now; try { when = File.GetLastWriteTime(file); } catch { }
            sp.Children.Add(Ui.Muted("On " + when.ToString("d MMM yyyy, HH:mm") + ". A report was saved on this PC - nothing was sent anywhere.", 12.5, 14));
            var row = new WrapPanel();
            row.Children.Add(Ui.Btn("Show details", () => { try { System.Diagnostics.Process.Start("notepad.exe", "\"" + file + "\""); } catch { } }));
            row.Children.Add(Ui.Btn("Open folder", () => { try { System.Diagnostics.Process.Start("explorer.exe", "/select,\"" + file + "\""); } catch { } }));
            var ok = Ui.Btn("OK", () => w.Close(), true); ok.MinWidth = 70; row.Children.Add(ok);
            sp.Children.Add(row); w.Content = sp;
            return w;
        }
    }
}
