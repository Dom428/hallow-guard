// Hallow Guard - small helpers for building WPF in code (no XAML compiler): colours, text, buttons, dark title bars.
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace HallowGuard
{
    public static class Ui
    {
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int val, int size);
        public static SolidColorBrush B(string hex) { var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); b.Freeze(); return b; }
        public static Brush R(string key) { return (Brush)Application.Current.FindResource(key); }
        public static Style S(string key) { return (Style)Application.Current.FindResource(key); }
        public static Brush Accent { get { return B(Program.AccentHex); } }
        static readonly Brush green = B("#6ED28C"), amber = B("#F0BE5A"), red = B("#E05A64");
        // the HUD looks take their status colours from the HUD palette (v1.7: Hallow console uses the family ones; Cyber blue its neon ones)
        public static Brush Green { get { return Look.IsHud ? Hud.Green : green; } }
        public static Brush Amber { get { return Look.IsHud ? Hud.Amber : amber; } }
        public static Brush Red { get { return Look.IsHud ? Hud.Red : red; } }
        // the highlight for icons and headings: the HUD glow (the Hallow accent in Hallow console, cyan in Cyber blue), the accent in classic
        public static Brush Hi { get { return Look.IsHud ? Hud.Glow : Accent; } }

        public static void Dress(Window w, string title, double width)
        {
            w.Title = title; w.Width = width; w.SizeToContent = SizeToContent.Height;
            Restyle(w); w.FontSize = 12.5;
            try { w.Icon = AppIcon(); } catch { }
            w.SourceInitialized += (s, e) => { int dark = 1; DwmSetWindowAttribute(new WindowInteropHelper(w).Handle, 20, ref dark, 4); };
        }
        // the window's colours and font for the current look (again after Settings > Look changes)
        public static void Restyle(Window w) { w.Background = R("Bg"); w.Foreground = R("Text"); w.FontFamily = Look.IsHud ? Hud.Body : new FontFamily("Segoe UI"); }
        static ImageSource icon;
        public static ImageSource AppIcon()
        {
            if (icon != null) return icon;
            var ico = System.Drawing.Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location);
            icon = Imaging.CreateBitmapSourceFromHIcon(ico.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions()); icon.Freeze();
            return icon;
        }
        public static TextBlock T(string text, double size = 12.5, bool bold = false, Brush fg = null, double bottom = 0)
        {
            var t = new TextBlock { Text = text, FontSize = size, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, bottom) };
            if (bold) t.FontWeight = FontWeights.SemiBold; if (fg != null) t.Foreground = fg;
            return t;
        }
        public static TextBlock Muted(string text, double size = 12, double bottom = 0) { return T(text, size, false, R("Muted"), bottom); }
        public static Button Btn(string label, Action click, bool accent = false, string tip = null)
        {
            var b = new Button { Content = label, Style = S(accent ? "Accent" : "Btn"), Margin = new Thickness(0, 0, 8, 0) };
            if (tip != null) b.ToolTip = tip;
            if (click != null) b.Click += (s, e) => click();
            return b;
        }
        public static StackPanel Row(params UIElement[] items) { var p = new StackPanel { Orientation = Orientation.Horizontal }; foreach (var i in items) p.Children.Add(i); return p; }
        public static Border Card(UIElement child, double pad = 18)
        {
            return new Border { Child = child, Background = R("Panel"), BorderBrush = R("Line"), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(14), Padding = new Thickness(pad) };
        }
        public static FrameworkElement Header(string word, double size = 22)
        {
            var title = new StackPanel { Orientation = Orientation.Horizontal };
            try { title.Children.Add(new Image { Source = AppIcon(), Width = size + 8, Height = size + 8, Margin = new Thickness(0, 0, 10, 0) }); } catch { }
            title.Children.Add(new TextBlock { Text = "HALLOW", FontSize = size, FontWeight = FontWeights.Bold, Foreground = Accent, VerticalAlignment = VerticalAlignment.Center });
            title.Children.Add(new TextBlock { Text = " " + word, FontSize = size, FontWeight = FontWeights.Light, VerticalAlignment = VerticalAlignment.Center });
            return title;
        }
        public static CheckBox Switch(string text, bool on, Action<bool> changed)
        {
            var c = new CheckBox { Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap }, IsChecked = on, Style = S("Switch") };
            c.Click += (s, e) => changed(c.IsChecked == true);
            return c;
        }
        public static PasswordBox PasswordField() { return new PasswordBox { Style = S("PasswordField"), Margin = new Thickness(0, 0, 0, 8) }; }
        public static TextBox Field(string text = "", double width = double.NaN) { var t = new TextBox { Text = text, Style = S("Field") }; if (!double.IsNaN(width)) t.Width = width; return t; }
    }
}
