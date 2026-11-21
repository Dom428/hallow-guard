// Hallow Guard - light and dark mode (v1.8, the family light/dark spec).
//   The family switch: "mode" in %APPDATA%\Hallow\theme.json ("dark" / "light" / "system"; missing = "dark"), written by Hallow
//   Toolkit - Guard only reads it. "system" = Windows' "app mode" (HKCU\...\Themes\Personalize AppsUseLightTheme, 1 = light),
//   followed live (Controller polls it every few seconds; theme.json changes come through the accent watcher).
//   Guard's own choice (Settings > Look): Follow Hallow (default) / Light / Dark - it wins over the family switch.
//   Hallow console and Hallow classic each have a light version; Cyber blue is dark only (the mode is ignored there).
// The light palette swaps the VALUES of the theme dictionaries (the resource keys stay the same) and the HUD palette (Hud.Use).
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Windows.Media;
using Microsoft.Win32;

namespace HallowGuard
{
    // Windows' app mode: true = light, false = dark, null = unknown (treated as dark)
    public interface ISystemTheme { bool? AppsUseLight(); }
    public class RegistrySystemTheme : ISystemTheme
    {
        public bool? AppsUseLight()
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    var v = k == null ? null : k.GetValue("AppsUseLightTheme");
                    if (v is int) return (int)v == 1;
                    return null;
                }
            }
            catch { return null; }
        }
    }
    public class FakeSystemTheme : ISystemTheme
    {
        public bool? Light; public int Reads;
        public bool? AppsUseLight() { Reads++; return Light; }
    }

    // the tray menu's colours (WinForms draws it): the family panel / hover / line / text values for each mode
    public class TrayColors : System.Windows.Forms.ProfessionalColorTable
    {
        public System.Drawing.Color Back, Hover, Line, Fore;
        public static TrayColors For(bool light)
        {
            Func<string, System.Drawing.Color> c = System.Drawing.ColorTranslator.FromHtml;
            return light ? new TrayColors { Back = c(Mode.LightPanel), Hover = c(Mode.LightPanel2), Line = c(Mode.LightLine), Fore = c(Mode.LightText) }
                         : new TrayColors { Back = c("#211B2A"), Hover = c("#3A3248"), Line = c("#3A3248"), Fore = c("#ECE8F4") };
        }
        public override System.Drawing.Color ToolStripDropDownBackground { get { return Back; } }
        public override System.Drawing.Color ImageMarginGradientBegin { get { return Back; } }
        public override System.Drawing.Color ImageMarginGradientMiddle { get { return Back; } }
        public override System.Drawing.Color ImageMarginGradientEnd { get { return Back; } }
        public override System.Drawing.Color MenuBorder { get { return Line; } }
        public override System.Drawing.Color MenuItemBorder { get { return Hover; } }
        public override System.Drawing.Color MenuItemSelected { get { return Hover; } }
        public override System.Drawing.Color MenuItemSelectedGradientBegin { get { return Hover; } }
        public override System.Drawing.Color MenuItemSelectedGradientEnd { get { return Hover; } }
        public override System.Drawing.Color SeparatorDark { get { return Line; } }
        public override System.Drawing.Color SeparatorLight { get { return Back; } }
        public override System.Drawing.Color CheckBackground { get { return Hover; } }
        public override System.Drawing.Color CheckSelectedBackground { get { return Hover; } }
        public override System.Drawing.Color CheckPressedBackground { get { return Hover; } }
    }

    public static class Mode
    {
        // Guard's own setting
        public const string Follow = "follow", Light = "light", Dark = "dark";
        // the family switch's third value
        public const string System = "system";
        public static ISystemTheme Sys = new RegistrySystemTheme();
        // the mode in use right now (set by Program.LoadTheme)
        public static bool IsLight;

        public static string Own(string s)
        {
            var v = (s ?? "").Trim().ToLowerInvariant();
            return v == Light ? Light : v == Dark ? Dark : Follow;
        }
        public static string Hallow(string s)
        {
            var v = (s ?? "").Trim().ToLowerInvariant();
            return v == Light ? Light : v == System ? System : Dark;     // missing / unknown = dark (today's look)
        }
        public static string OwnLabel(string s) { s = Own(s); return s == Light ? "Light" : s == Dark ? "Dark" : "Follow Hallow"; }

        // light or dark: Cyber blue is always dark; Guard's own Light/Dark wins; else the family switch ("system" = Windows' app mode)
        public static bool Resolve(string look, string own, string hallow, ISystemTheme sys)
        {
            if (Look.Normalize(look) == Look.CyberBlueName) return false;
            own = Own(own);
            if (own == Light) return true;
            if (own == Dark) return false;
            hallow = Hallow(hallow);
            if (hallow == Light) return true;
            if (hallow == System) { bool? v = null; try { v = sys == null ? null : sys.AppsUseLight(); } catch { } return v == true; }
            return false;
        }
        // where the answer came from (Settings shows it)
        public static string Why(string look, string own, string hallow)
        {
            if (Look.Normalize(look) == Look.CyberBlueName) return "Cyber blue is always dark";
            own = Own(own);
            if (own != Follow) return "your choice here";
            hallow = Hallow(hallow);
            return hallow == System ? "Hallow follows Windows" : hallow == Light ? "Hallow is set to light" : "Hallow is set to dark";
        }

        // ---- colour maths
        static Color Hex(string s) { return (Color)ColorConverter.ConvertFromString(s); }
        static string ToHex(Color c) { return "#" + c.R.ToString("X2") + c.G.ToString("X2") + c.B.ToString("X2"); }
        public static double Ratio(string a, string b) { return Hud.Ratio(Hex(a), Hex(b)); }
        static void ToHsl(Color c, out double h, out double s, out double l)
        {
            double r = c.R / 255.0, g = c.G / 255.0, b = c.B / 255.0, max = Math.Max(r, Math.Max(g, b)), min = Math.Min(r, Math.Min(g, b));
            l = (max + min) / 2; h = 0; s = 0;
            if (max == min) return;
            var d = max - min; s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
            if (max == r) h = (g - b) / d + (g < b ? 6 : 0); else if (max == g) h = (b - r) / d + 2; else h = (r - g) / d + 4;
            h /= 6;
        }
        static Color FromHsl(double h, double s, double l)
        {
            Func<double, double, double, double> f = (p, q, t) => { if (t < 0) t += 1; if (t > 1) t -= 1; return t < 1 / 6.0 ? p + (q - p) * 6 * t : t < 0.5 ? q : t < 2 / 3.0 ? p + (q - p) * (2 / 3.0 - t) * 6 : p; };
            double r, g, b;
            if (s == 0) r = g = b = l;
            else { var q = l < 0.5 ? l * (1 + s) : l + s - l * s; var p = 2 * l - q; r = f(p, q, h + 1 / 3.0); g = f(p, q, h); b = f(p, q, h - 1 / 3.0); }
            return Color.FromRgb((byte)Math.Round(r * 255), (byte)Math.Round(g * 255), (byte)Math.Round(b * 255));
        }
        // the accent for TEXT and thin lines on the light backgrounds: darkened in HSL until it reads at 4.5:1 on white AND on the
        // light page background (#F6F4FA) - the default orange becomes about #B5540C. An accent that already reads well is kept.
        public static string TextAccent(string accent)
        {
            Color c; try { c = Hex(accent); } catch { c = Hex(Accent.Default); }
            double h, s, l; ToHsl(c, out h, out s, out l);
            var x = c;
            while ((Hud.Ratio(x, Colors.White) < 4.5 || Hud.Ratio(x, Hex(LightBg)) < 4.5) && l > 0) { l = Math.Max(0, l - 0.005); x = FromHsl(h, s, l); }
            return ToHex(x);
        }

        // ---- the light palette (the family spec)
        public const string LightBg = "#F6F4FA", LightPanel = "#FFFFFF", LightPanel2 = "#EEEAF5", LightLine = "#DAD3E6", LightText = "#1E1A26",
            LightMuted = "#6B6478", LightLilac = "#7A5CC0", LightGreen = "#1E8E4F", LightAmber = "#A66A00", LightRed = "#C2333F",
            LightInfo = "#2F65A8", LightLow = "#8A6A00", LightNav = "#3A3448", LightHoverLine = "#B9AED0";

        // Hallow classic's dictionary (Theme.xaml) in light: dark value -> light value. The accent's TEXT uses (caret, focus border)
        // become the darkened accent first; its FILLS (Accent button, checked chip, progress) keep the real accent with dark text.
        static readonly string[,] classicMap = {
            { "#16121C", LightBg }, { "#211B2A", LightPanel }, { "#2E2639", LightPanel2 }, { "#3A3248", LightLine }, { "#ECE8F4", LightText },
            { "#8F88A0", LightMuted }, { "#C8414B", LightRed }, { "#E05A64", LightRed }, { "#2A2333", LightPanel2 }, { "#55496A", LightHoverLine },
            { "#58566A", "#8F87A3" }, { "#CDCAD6", "#FFFFFF" }, { "#241E2E", LightPanel }, { "#1A1522", LightPanel }, { "#3A2F4A", "#E4DCF3" },
            { "#A98BE0", LightLilac }, { "#6ED28C", LightGreen } };
        // Hallow console's dictionary (ThemeConsole.xaml) in light
        static readonly string[,] consoleMap = {
            { "#14101B", LightBg }, { "#1C1726", LightPanel }, { "#221C2E", LightPanel2 }, { "#3A3248", LightLine }, { "#ECE8F4", LightText },
            { "#9790A8", LightMuted }, { "#1E1829", LightPanel }, { "#463C58", LightHoverLine }, { "#4A4060", LightHoverLine }, { "#6E6684", "#8A8298" },
            { "#1B3326", "#DDF1E5" }, { "#6ED28C", LightGreen }, { "#120E18", LightPanel }, { "#6E5A96", LightHoverLine }, { "#A98BE0", LightLilac },
            { "#D6D0E2", LightNav } };

        public static string LightClassic(string xaml, string textAccent) { return Swap(xaml, classicMap, textAccent); }
        public static string LightConsole(string xaml, string textAccent) { return Swap(xaml, consoleMap, textAccent); }
        static string Swap(string xaml, string[,] map, string ta)
        {
            // the accent where it is text or a thin line -> the darkened accent (before Accent.ApplyTo swaps the rest for the real accent)
            xaml = Regex.Replace(xaml, "(Property=\"(?:CaretBrush|BorderBrush|Foreground)\" Value=\")#(?:F07820|F59A50)\"", "${1}" + ta + "\"", RegexOptions.IgnoreCase);
            xaml = Regex.Replace(xaml, "((?:Stroke|BorderBrush)=\")#F07820\"", "${1}" + ta + "\"", RegexOptions.IgnoreCase);
            // no glows in light mode: the accent border / bar that carries each glow stays, the blur goes
            xaml = Regex.Replace(xaml, "(<DropShadowEffect [^>]*?Opacity=\")[0-9.]+\"", "${1}0\"");
            xaml = Regex.Replace(xaml, "<DropShadowEffect (?![^>]*Opacity=)", "<DropShadowEffect Opacity=\"0\" ");
            // the button hover wash: white on dark, a lilac tint on light
            xaml = xaml.Replace("x:Name=\"hl\" Background=\"#FFFFFF\"", "x:Name=\"hl\" Background=\"#7A5CC0\"");
            for (int i = 0; i < map.GetLength(0); i++) xaml = Regex.Replace(xaml, Regex.Escape(map[i, 0]) + "(?![0-9A-Fa-f])", map[i, 1], RegexOptions.IgnoreCase);
            return xaml;
        }
    }
}
