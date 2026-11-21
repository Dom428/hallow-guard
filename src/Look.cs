// Hallow Guard - the look. v1.7: three looks - "console" (the default: the security-console HUD in the Hallow palette - dark
// purple-black, the Hallow accent as the glow, lilac secondary lines, the family's green / amber / red), "classic" (the 1.3 look,
// untouched) and "cyberblue" (the 1.4 cyan HUD, kept for whoever liked it). Saved "cyber" (1.4-1.6) becomes "console".
// Also the HUD building blocks (fonts, colours, cards with corner brackets, status LEDs, the radar ring, segmented bars, the hex grid) and
// the animation gate: animations only run while the window is visible and focused, no game or full-screen app is running and
// Windows' "Show animations" is on. Otherwise every animated part shows a still frame - and costs nothing.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Shapes;

namespace HallowGuard
{
    public static class Look
    {
        public const string ConsoleName = "console", ClassicName = "classic", CyberBlueName = "cyberblue";
        public static string Current = ConsoleName;
        // the HUD layout (radar, brackets, console...): Hallow console and Cyber blue; Hallow classic is the plain 1.3 layout
        public static bool IsHud { get { return Current != ClassicName; } }
        public static bool IsCyberBlue { get { return Current == CyberBlueName; } }
        // "classic" and "cyberblue" are kept; anything else - including the 1.4-1.6 "cyber" (the default then, never a deliberate
        // choice of cyan) - is the default Hallow console
        public static string Normalize(string s)
        {
            var v = s == null ? "" : s.Trim().ToLowerInvariant().Replace(" ", "").Replace("-", "");
            return v == ClassicName ? ClassicName : v == CyberBlueName ? CyberBlueName : ConsoleName;
        }
        public static string Label(string look) { look = Normalize(look); return look == ClassicName ? "Hallow classic" : look == CyberBlueName ? "Cyber blue" : "Hallow console"; }
    }

    // ---------------- the animation gate
    public interface IViewState { bool Visible { get; } bool Minimized { get; } bool Focused { get; } }
    public class WindowView : IViewState
    {
        readonly Window w; public WindowView(Window w) { this.w = w; }
        public bool Visible { get { return w.IsVisible; } }
        public bool Minimized { get { return w.WindowState == WindowState.Minimized; } }
        public bool Focused { get { return w.IsActive; } }
    }
    public class FakeView : IViewState
    {
        public bool Visible = true, Minimized, Focused = true;
        bool IViewState.Visible { get { return Visible; } }
        bool IViewState.Minimized { get { return Minimized; } }
        bool IViewState.Focused { get { return Focused; } }
    }

    // Each animated part registers an Action<bool>: true = run, false = stop and show the still frame. Update() is cheap: the
    // window checks come first, and "is a game running" (a process lookup) is only asked when everything else says yes, at most
    // every BusyCache, and never when nothing on the page animates.
    public class AnimGate
    {
        readonly IViewState view; readonly IBusySource busy; readonly Func<bool> sysAnim;
        readonly List<Action<bool>> parts = new List<Action<bool>>();
        public bool Running { get; private set; }
        public string Why { get; private set; }
        public bool Disabled;                                 // --snap: always the still frame
        public int BusyChecks;                                // how often the game check was asked (tests)
        public TimeSpan BusyCache = TimeSpan.FromSeconds(3);
        string busyValue; int busyAt; bool busyKnown;

        public AnimGate(IViewState view, IBusySource busy, Func<bool> sysAnim) { this.view = view; this.busy = busy; this.sysAnim = sysAnim; Why = "not started"; }
        public int Parts { get { return parts.Count; } }

        // why the animations are paused, or null when they may run
        public static string Reason(bool visible, bool minimized, bool focused, bool sysAnim, Func<string> busyNow)
        {
            if (!visible) return "hidden";
            if (minimized) return "minimized";
            if (!focused) return "not focused";
            if (!sysAnim) return "Windows animations are off";
            return busyNow == null ? null : busyNow();
        }
        string Busy()
        {
            if (busy == null) return null;
            if (busyKnown && BusyCache > TimeSpan.Zero && unchecked(Environment.TickCount - busyAt) < BusyCache.TotalMilliseconds) return busyValue;
            BusyChecks++;
            try { busyValue = busy.Busy(); } catch { busyValue = null; }
            busyAt = Environment.TickCount; busyKnown = true;
            return busyValue;
        }
        public bool Update()
        {
            string why;
            if (Disabled) why = "snapshot";
            else if (parts.Count == 0) why = "nothing to animate";
            else
            {
                bool sys; try { sys = sysAnim == null || sysAnim(); } catch { sys = true; }
                why = Reason(view.Visible, view.Minimized, view.Focused, sys, Busy);
            }
            Why = why;
            bool run = why == null;
            if (run != Running) { Running = run; foreach (var p in parts.ToArray()) { try { p(run); } catch { } } }
            return Running;
        }
        public void Add(Action<bool> part) { if (part == null) return; parts.Add(part); try { part(Running); } catch { } }
        // a new page: the old parts are gone with it
        public void Clear() { foreach (var p in parts.ToArray()) { try { p(false); } catch { } } parts.Clear(); }
        public void ForgetBusy() { busyKnown = false; }
    }

    // ---------------- the HUD building blocks
    public static class Hud
    {
        public static SolidColorBrush B(string hex) { return Ui.B(hex); }
        // v1.7: the palette depends on the look (Use() is called by Program.LoadTheme, again when theme.json changes).
        //   Glow  = the primary glow, borders, sweep, the open page's bar: the Hallow accent in Hallow console (cyan in Cyber blue)
        //   Lilac = secondary lines, the hex grid, codes and labels
        public static Brush Bg, Panel, PanelHi, Line, LineDim, Text, Muted, Glow, Lilac, Green, Amber, Red, Info, Low, Console, Dim, Side, Well, Node;
        public static string GlowHex { get; private set; }
        static Color cardTop, cardBottom, discIn, discMid, discOut;
        static Hud() { Use(Look.ConsoleName, Accent.Default); }

        public static void Use(string look, string accent)
        {
            if (Look.Normalize(look) == Look.CyberBlueName)
            {
                Bg = B("#070B12"); Panel = B("#0B1320"); PanelHi = B("#102033"); Line = B("#1A3550"); LineDim = B("#122638");
                Text = B("#DDF6FF"); Muted = B("#8AA6BA"); Glow = B("#22E1FF"); Lilac = B("#22E1FF"); Green = B("#39FF88"); Amber = B("#FFB547"); Red = B("#FF3D6E"); Info = B("#7AB0FF"); Low = B("#FFE07A");
                Console = B("#04080D"); Dim = B("#16293B"); Side = B("#05090F"); Well = B("#08131E"); Node = B("#0C2230");
                cardTop = Hex("#F20E1828"); cardBottom = Hex("#F20A111C"); discIn = Hex("#0F2436"); discMid = Hex("#0A1422"); discOut = Hex("#070B12");
                GlowHex = "#22E1FF";
            }
            else
            {
                // the family's dark purple-black (Mixer, Hub, Assist...: #16121C / #211B2A / #3A3248) and its status colours
                Bg = B("#14101B"); Panel = B("#1C1726"); PanelHi = B("#221C2E"); Line = B("#3A3248"); LineDim = B("#2A2336");
                Text = B("#ECE8F4"); Muted = B("#9790A8"); Lilac = B("#A98BE0"); Green = B("#6ED28C"); Amber = B("#F0BE5A"); Red = B("#E05A64"); Info = B("#A98BE0"); Low = B("#E8D27A");
                Console = B("#100D16"); Dim = B("#2E2640"); Side = B("#110E17"); Well = B("#18131F");
                cardTop = Hex("#F21E1828"); cardBottom = Hex("#F217121F"); discIn = Hex("#2A2236"); discMid = Hex("#1C1726"); discOut = Hex("#14101B");
                GlowHex = Readable(Valid(accent) ? accent.ToUpperInvariant() : Accent.Default, Hex("#221C2E"));
                Glow = B(GlowHex);
                Node = new SolidColorBrush(Mix(Hex("#14101B"), Hex(GlowHex), 0.16)); Node.Freeze();
            }
            cardBg = cardLine = hex = null;    // rebuilt with the new colours
        }
        // the card gradient's ends (as solid colours, for the contrast test)
        public static Brush CardTop { get { return B("#" + cardTop.R.ToString("X2") + cardTop.G.ToString("X2") + cardTop.B.ToString("X2")); } }
        public static Brush CardBottom { get { return B("#" + cardBottom.R.ToString("X2") + cardBottom.G.ToString("X2") + cardBottom.B.ToString("X2")); } }
        static bool Valid(string s) { return s != null && System.Text.RegularExpressions.Regex.IsMatch(s, "^#[0-9A-Fa-f]{6}$"); }
        static Color Hex(string s) { return (Color)ColorConverter.ConvertFromString(s); }
        public static Color Mix(Color a, Color b, double k) { return Color.FromArgb(255, (byte)Math.Round(a.R + (b.R - a.R) * k), (byte)Math.Round(a.G + (b.G - a.G) * k), (byte)Math.Round(a.B + (b.B - a.B) * k)); }
        public static double Lum(Color c)
        {
            Func<byte, double> f = v => { var x = v / 255.0; return x <= 0.03928 ? x / 12.92 : Math.Pow((x + 0.055) / 1.055, 2.4); };
            return 0.2126 * f(c.R) + 0.7152 * f(c.G) + 0.0722 * f(c.B);
        }
        public static double Ratio(Color a, Color b) { double x = Lum(a), y = Lum(b); return (Math.Max(x, y) + 0.05) / (Math.Min(x, y) + 0.05); }
        // the accent as it is when it reads well on the panels (>= 4.5:1, the default orange does); a dark accent is lightened until it does
        public static string Readable(string accent, Color on)
        {
            var c = Hex(accent);
            for (int i = 0; i <= 20 && Ratio(c, on) < 4.6; i++) c = Mix(Hex(accent), Colors.White, i * 0.05);
            return Ratio(Hex(accent), on) >= 4.6 ? accent : "#" + c.R.ToString("X2") + c.G.ToString("X2") + c.B.ToString("X2");
        }
        public static readonly FontFamily Mono = new FontFamily("Cascadia Mono, Consolas, Courier New");
        public static readonly FontFamily Head = new FontFamily("Bahnschrift, Segoe UI Variable Display, Segoe UI");
        public static readonly FontFamily Body = new FontFamily("Segoe UI Variable Text, Segoe UI");
        public static Color C(Brush b) { var s = b as SolidColorBrush; return s == null ? Colors.White : s.Color; }
        public static SolidColorBrush Alpha(Brush b, double a) { var c = C(b); var r = new SolidColorBrush(Color.FromArgb((byte)(a * 255), c.R, c.G, c.B)); r.Freeze(); return r; }

        // letter-spaced capitals for headings (WPF has no letter spacing: hair spaces between the letters; the screen reader name
        // stays the plain text)
        public static string Spaced(string s)
        {
            var sb = new StringBuilder();
            foreach (var ch in (s ?? "").ToUpperInvariant()) { if (sb.Length > 0) sb.Append(' '); sb.Append(ch == ' ' ? " " : ch.ToString()); }
            return sb.ToString();
        }
        public static TextBlock Caps(string text, double size, Brush fg, double bottom = 0)
        {
            var t = new TextBlock { Text = Spaced(text), FontFamily = Head, FontSize = size, FontWeight = FontWeights.SemiBold, Foreground = fg ?? Text, Margin = new Thickness(0, 0, 0, bottom), TextWrapping = TextWrapping.NoWrap };
            AutomationProperties.SetName(t, text);
            return t;
        }
        public static TextBlock M(string text, double size, Brush fg, double bottom = 0)
        {
            return new TextBlock { Text = text, FontFamily = Mono, FontSize = size, Foreground = fg ?? Muted, Margin = new Thickness(0, 0, 0, bottom), TextWrapping = TextWrapping.NoWrap, TextTrimming = TextTrimming.CharacterEllipsis };
        }

        // status: colour, the code shown next to it (never colour alone) and the LED
        public static Brush StateColor(CheckState s) { return s == CheckState.Good ? Green : s == CheckState.Warn ? Amber : s == CheckState.Bad ? Red : s == CheckState.Info ? Info : Muted; }
        public static string Code(CheckState s, bool notInstalled = false)
        {
            if (notInstalled) return "[N/A]";
            return s == CheckState.Good ? "[OK]" : s == CheckState.Warn ? "[WARN]" : s == CheckState.Bad ? "[RISK]" : s == CheckState.Info ? "[INFO]" : "[UNK]";
        }
        public static Brush ScoreColor(int s) { return s >= 90 ? Green : s >= 70 ? Amber : Red; }
        public static string Status(int s) { return s < 0 ? "SCANNING" : s >= 90 ? "SECURE" : s >= 70 ? "ATTENTION" : "AT RISK"; }

        public static FrameworkElement Led(Brush color, double size = 8)
        {
            var g = new Grid { Width = size * 2.6, Height = size * 2.6, VerticalAlignment = VerticalAlignment.Center, IsHitTestVisible = false };
            var c = C(color);
            var glow = new RadialGradientBrush(); glow.GradientStops.Add(new GradientStop(Color.FromArgb(150, c.R, c.G, c.B), 0)); glow.GradientStops.Add(new GradientStop(Color.FromArgb(40, c.R, c.G, c.B), 0.45)); glow.GradientStops.Add(new GradientStop(Color.FromArgb(0, c.R, c.G, c.B), 1)); glow.Freeze();
            g.Children.Add(new Ellipse { Fill = glow });
            g.Children.Add(new Ellipse { Width = size, Height = size, Fill = color, Stroke = Alpha(Brushes.White, 0.55), StrokeThickness = 0.8 });
            return g;
        }

        // the HUD frame: L-shaped corner brackets
        public static Grid Brackets(Brush color, double len = 10, double th = 1.6)
        {
            var g = new Grid { IsHitTestVisible = false, Margin = new Thickness(-1) };
            foreach (var corner in new[] { "tl", "tr", "bl", "br" })
            {
                bool left = corner[1] == 'l', top = corner[0] == 't';
                var data = string.Format(System.Globalization.CultureInfo.InvariantCulture, top ? (left ? "M0,{0} L0,0 L{0},0" : "M0,0 L{0},0 L{0},{0}") : (left ? "M0,0 L0,{0} L{0},{0}" : "M0,{0} L{0},{0} L{0},0"), len);
                g.Children.Add(new Path { Data = Geometry.Parse(data), Stroke = color, StrokeThickness = th, Width = len, Height = len, HorizontalAlignment = left ? HorizontalAlignment.Left : HorizontalAlignment.Right, VerticalAlignment = top ? VerticalAlignment.Top : VerticalAlignment.Bottom, SnapsToDevicePixels = true });
            }
            return g;
        }
        static Brush cardBg, cardLine;
        public static Brush CardBg
        {
            get
            {
                if (cardBg != null) return cardBg;
                var g = new LinearGradientBrush { StartPoint = new Point(0, 0), EndPoint = new Point(0, 1) };
                g.GradientStops.Add(new GradientStop(cardTop, 0)); g.GradientStops.Add(new GradientStop(cardBottom, 1)); g.Freeze();
                return cardBg = g;
            }
        }
        public static Brush CardLine
        {
            get
            {
                if (cardLine != null) return cardLine;
                var g = new LinearGradientBrush { StartPoint = new Point(0, 0), EndPoint = new Point(1, 1) };
                var gl = C(Glow); var ln = C(Line); var dm = C(Dim);
                g.GradientStops.Add(new GradientStop(Color.FromArgb(150, gl.R, gl.G, gl.B), 0)); g.GradientStops.Add(new GradientStop(ln, 0.35)); g.GradientStops.Add(new GradientStop(dm, 1)); g.Freeze();
                return cardLine = g;
            }
        }
        // a card: thin glowing border, corner brackets; the returned Border's BorderBrush can still be changed by the caller
        public static Border Card(UIElement child, Thickness pad, double bottom, Brush bracket = null)
        {
            var inner = new Grid();
            inner.Children.Add(new Border { Child = child, Padding = pad });
            inner.Children.Add(Brackets(bracket ?? Alpha(Glow, 0.85)));
            return new Border { Child = inner, Background = CardBg, BorderBrush = CardLine, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(2), Margin = new Thickness(0, 0, 0, bottom) };
        }
        // a tag-style chip: [SEV:HIGH]
        public static Border Tag(string text, Brush color)
        {
            var b = new Border { BorderBrush = color, BorderThickness = new Thickness(1), Background = Alpha(color, 0.1), CornerRadius = new CornerRadius(2), Padding = new Thickness(6, 1, 6, 1), VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
            b.Child = new TextBlock { Text = text.ToUpperInvariant(), FontFamily = Mono, FontSize = 10.5, FontWeight = FontWeights.SemiBold, Foreground = color };
            return b;
        }
        public static FrameworkElement Divider(double top = 8, double bottom = 8) { return new Rectangle { Height = 1, Fill = LineDim, Margin = new Thickness(0, top, 0, bottom), SnapsToDevicePixels = true }; }

        // ---- backgrounds: a faint hex grid and a vignette
        static Brush hex, vignette, scan;
        public static Brush HexGrid
        {
            get
            {
                if (hex != null) return hex;
                double a = 11, h = Math.Sqrt(3) * a;
                var geo = Geometry.Parse(string.Format(System.Globalization.CultureInfo.InvariantCulture, "M0,{1} L{2},0 L{3},0 L{4},{1} L{3},{5} L{2},{5} Z M{4},{1} L{6},{1}", 0, h / 2, a / 2, 1.5 * a, 2 * a, h, 3 * a));
                var d = new GeometryDrawing(null, new Pen(Alpha(Lilac, Look.IsCyberBlue ? 0.07 : 0.09), 1), geo);
                var b = new DrawingBrush(d) { TileMode = TileMode.Tile, Viewport = new Rect(0, 0, 3 * a, h), ViewportUnits = BrushMappingMode.Absolute, Viewbox = new Rect(0, 0, 3 * a, h), ViewboxUnits = BrushMappingMode.Absolute, Stretch = Stretch.None };
                RenderOptions.SetCachingHint(b, CachingHint.Cache); b.Freeze();
                return hex = b;
            }
        }
        public static Brush Vignette
        {
            get
            {
                if (vignette != null) return vignette;
                var v = new RadialGradientBrush { Center = new Point(0.55, 0.35), GradientOrigin = new Point(0.55, 0.35), RadiusX = 0.85, RadiusY = 0.95 };
                v.GradientStops.Add(new GradientStop(Color.FromArgb(0, 0, 0, 0), 0.45)); v.GradientStops.Add(new GradientStop(Color.FromArgb(150, 0, 0, 0), 1)); v.Freeze();
                return vignette = v;
            }
        }
        public static Brush Scanlines
        {
            get
            {
                if (scan != null) return scan;
                var d = new GeometryDrawing(Alpha(Brushes.Black, 0.45), null, new RectangleGeometry(new Rect(0, 0, 4, 1)));
                var g = new DrawingGroup(); g.Children.Add(new GeometryDrawing(Brushes.Transparent, null, new RectangleGeometry(new Rect(0, 0, 4, 3)))); g.Children.Add(d);
                var b = new DrawingBrush(g) { TileMode = TileMode.Tile, Viewport = new Rect(0, 0, 4, 3), ViewportUnits = BrushMappingMode.Absolute, Stretch = Stretch.None };
                b.Freeze(); return scan = b;
            }
        }

        // ---- motion helpers: 24 frames a second is plenty for this
        public static DoubleAnimation Loop(double from, double to, double seconds, bool reverse = false)
        {
            var a = new DoubleAnimation(from, to, TimeSpan.FromSeconds(seconds)) { RepeatBehavior = RepeatBehavior.Forever, AutoReverse = reverse };
            if (reverse) a.EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut };
            Timeline.SetDesiredFrameRate(a, 24);
            return a;
        }
        // run the animation while the gate allows, else the still frame
        public static Action<bool> Animate(Animatable target, DependencyProperty prop, Func<DoubleAnimation> make, double still)
        {
            return run => { if (run) target.BeginAnimation(prop, make()); else { target.BeginAnimation(prop, null); target.SetValue(prop, still); } };
        }
        public static Action<bool> Animate(UIElement target, DependencyProperty prop, Func<DoubleAnimation> make, double still)
        {
            return run => { if (run) target.BeginAnimation(prop, make()); else { target.BeginAnimation(prop, null); target.SetValue(prop, still); } };
        }

        // ---- segmented bar (sub-scores)
        public static FrameworkElement SegBar(string label, int? value, int segs = 24)
        {
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 6) };
            var l = M(label.ToUpperInvariant(), 10.5, Muted); l.Width = 150; l.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(l, Dock.Left); row.Children.Add(l);
            var v = M(value == null ? "--" : value.Value.ToString().PadLeft(3), 11.5, value == null ? Muted : ScoreColor(value.Value)); v.FontWeight = FontWeights.SemiBold; v.Width = 34; v.TextAlignment = TextAlignment.Right; v.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(v, Dock.Right); row.Children.Add(v);
            var bar = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            int lit = value == null ? 0 : (int)Math.Round(value.Value / 100.0 * segs);
            var on = value == null ? Muted : ScoreColor(value.Value);
            for (int i = 0; i < segs; i++) bar.Children.Add(new Rectangle { Width = 7, Height = 10, Margin = new Thickness(0, 0, 2, 0), Fill = i < lit ? on : Dim, SnapsToDevicePixels = true });
            row.Children.Add(bar);
            AutomationProperties.SetName(row, label + ": " + (value == null ? "none" : value + " of 100"));
            return row;
        }

        // ---- the radar ring: tick marks, a segmented arc, a sweep line (while checking) and a pulsing glow (when secure)
        public class Radar
        {
            public FrameworkElement View; public Action<bool> Sweep, Pulse; public TextBlock Number;
            readonly List<Path> segs = new List<Path>(); readonly Brush on; int shown;
            public Radar(int score, double size, bool sweeping)
            {
                var c = new Canvas { Width = size, Height = size };
                double cx = size / 2, cy = size / 2, rOut = size / 2 - 2, rSeg = size / 2 - 18, th = 11;
                on = score < 0 ? Glow : ScoreColor(score);
                var disc = new RadialGradientBrush(); disc.GradientStops.Add(new GradientStop(discIn, 0)); disc.GradientStops.Add(new GradientStop(discMid, 0.7)); disc.GradientStops.Add(new GradientStop(discOut, 1)); disc.Freeze();
                var bg = new Ellipse { Width = 2 * (rSeg - th), Height = 2 * (rSeg - th), Fill = disc }; Canvas.SetLeft(bg, cx - (rSeg - th)); Canvas.SetTop(bg, cy - (rSeg - th)); c.Children.Add(bg);
                // the glow (behind the segments)
                var glow = new Ellipse { Width = 2 * rSeg, Height = 2 * rSeg, Stroke = on, StrokeThickness = th + 6, Opacity = 0.35, Effect = new BlurEffect { Radius = 14 } };
                Canvas.SetLeft(glow, cx - rSeg); Canvas.SetTop(glow, cy - rSeg);
                if (score >= 90) { c.Children.Add(glow); Pulse = Animate(glow, UIElement.OpacityProperty, () => Loop(0.15, 0.55, 1.6, true), 0.4); }
                // ticks: 72, every 6th longer
                var ticks = new StreamGeometry(); var major = new StreamGeometry();
                using (var g = ticks.Open()) using (var m = major.Open())
                    for (int i = 0; i < 72; i++)
                    {
                        double a = i * 5 * Math.PI / 180, l = i % 6 == 0 ? 7 : 3.5; var ctx = i % 6 == 0 ? m : g;
                        ctx.BeginFigure(new Point(cx + rOut * Math.Sin(a), cy - rOut * Math.Cos(a)), false, false);
                        ctx.LineTo(new Point(cx + (rOut - l) * Math.Sin(a), cy - (rOut - l) * Math.Cos(a)), true, false);
                    }
                ticks.Freeze(); major.Freeze();
                c.Children.Add(new Path { Data = ticks, Stroke = Alpha(Lilac, 0.35), StrokeThickness = 1 });
                c.Children.Add(new Path { Data = major, Stroke = Alpha(Glow, 0.8), StrokeThickness = 1.4 });
                // 50 segments
                for (int i = 0; i < 50; i++)
                {
                    double a0 = (i * 7.2 + 0.9) * Math.PI / 180, a1 = ((i + 1) * 7.2 - 0.9) * Math.PI / 180;
                    var f = new PathFigure { StartPoint = new Point(cx + rSeg * Math.Sin(a0), cy - rSeg * Math.Cos(a0)) };
                    f.Segments.Add(new ArcSegment(new Point(cx + rSeg * Math.Sin(a1), cy - rSeg * Math.Cos(a1)), new Size(rSeg, rSeg), 0, false, SweepDirection.Clockwise, true));
                    var pg = new PathGeometry(); pg.Figures.Add(f); pg.Freeze();
                    var p = new Path { Data = pg, StrokeThickness = th, Stroke = Dim }; segs.Add(p); c.Children.Add(p);
                }
                // inner ring and cross-hair
                var inner = new Ellipse { Width = 2 * (rSeg - th - 6), Height = 2 * (rSeg - th - 6), Stroke = Alpha(Lilac, 0.3), StrokeThickness = 1, StrokeDashArray = new DoubleCollection { 2, 3 } };
                Canvas.SetLeft(inner, cx - (rSeg - th - 6)); Canvas.SetTop(inner, cy - (rSeg - th - 6)); c.Children.Add(inner);
                var cross = new StreamGeometry(); double rc = rSeg - th - 6;
                using (var g = cross.Open()) { g.BeginFigure(new Point(cx - rc, cy), false, false); g.LineTo(new Point(cx - rc + 10, cy), true, false); g.BeginFigure(new Point(cx + rc - 10, cy), false, false); g.LineTo(new Point(cx + rc, cy), true, false); g.BeginFigure(new Point(cx, cy - rc), false, false); g.LineTo(new Point(cx, cy - rc + 10), true, false); g.BeginFigure(new Point(cx, cy + rc - 10), false, false); g.LineTo(new Point(cx, cy + rc), true, false); }
                cross.Freeze(); c.Children.Add(new Path { Data = cross, Stroke = Alpha(Lilac, 0.5), StrokeThickness = 1 });
                // the sweep: a fading wedge behind a bright line, turning round the centre
                if (sweeping)
                {
                    double rs = rSeg + th / 2;
                    var wedge = new StreamGeometry();
                    using (var g = wedge.Open())
                    {
                        g.BeginFigure(new Point(cx, cy), true, true);
                        g.LineTo(new Point(cx, cy - rs), true, false);
                        double a = -55 * Math.PI / 180;
                        g.ArcTo(new Point(cx + rs * Math.Sin(a), cy - rs * Math.Cos(a)), new Size(rs, rs), 0, false, SweepDirection.Counterclockwise, true, false);
                    }
                    wedge.Freeze();
                    var fill = new LinearGradientBrush { StartPoint = new Point(1, 0.5), EndPoint = new Point(0, 0.9) };
                    var gw = C(Glow); fill.GradientStops.Add(new GradientStop(Color.FromArgb(110, gw.R, gw.G, gw.B), 0)); fill.GradientStops.Add(new GradientStop(Color.FromArgb(0, gw.R, gw.G, gw.B), 1)); fill.Freeze();
                    var sw = new Canvas { Width = size, Height = size, IsHitTestVisible = false };
                    sw.Children.Add(new Path { Data = wedge, Fill = fill });
                    sw.Children.Add(new Line { X1 = cx, Y1 = cy, X2 = cx, Y2 = cy - rs, Stroke = Glow, StrokeThickness = 1.6, Effect = new DropShadowEffect { Color = C(Glow), BlurRadius = 8, ShadowDepth = 0, Opacity = 0.9 } });
                    var rot = new RotateTransform(35, cx, cy); sw.RenderTransform = rot; c.Children.Add(sw);
                    Sweep = Animate(rot, RotateTransform.AngleProperty, () => Loop(0, 360, 3.2), 35);
                }
                // the number
                var mid = new StackPanel { Width = size, VerticalAlignment = VerticalAlignment.Center };
                Number = new TextBlock { Text = score < 0 ? "--" : score.ToString(), FontFamily = Head, FontSize = size * 0.25, FontWeight = FontWeights.SemiBold, Foreground = on, HorizontalAlignment = HorizontalAlignment.Center };
                mid.Children.Add(Number);
                mid.Children.Add(new TextBlock { Text = "/100", FontFamily = Mono, FontSize = 11, Foreground = Muted, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, -4, 0, 2) });
                mid.Children.Add(new TextBlock { Text = Spaced("integrity"), FontFamily = Head, FontSize = 9.5, Foreground = Alpha(Lilac, 0.95), HorizontalAlignment = HorizontalAlignment.Center });
                Canvas.SetTop(mid, cy - size * 0.21); c.Children.Add(mid);
                c.SnapsToDevicePixels = false;
                AutomationProperties.SetName(c, score < 0 ? "Checking" : "Safety score " + score + " of 100, " + Status(score).ToLowerInvariant());
                View = c;
                Show(Math.Max(0, score));
            }
            // lights the segments up to this score (the count-up calls it every frame)
            public void Show(int value)
            {
                shown = value; int lit = (int)Math.Round(value / 2.0);
                for (int i = 0; i < segs.Count; i++) segs[i].Stroke = i < lit ? on : Dim;
            }
        }
    }
}
