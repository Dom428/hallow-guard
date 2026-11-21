// Hallow Guard 1.8 tests: light and dark mode (the family spec). Mode resolution (theme.json missing -> dark, "system" -> Windows'
// app mode through a fake, Guard's own Light/Dark wins, Cyber blue ignores the mode), reading "mode" from a TEST theme.json (never the
// real one), the setting and its migration, the darkened accent, the light palette's contrast (text >= 4.5:1, status colours and
// icons >= 3:1), and the light theme dictionaries (same keys, no dark values left, no glows).
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows.Media;

namespace HallowGuard.Tests
{
    public static class V18Tests
    {
        static Action<bool, string> Ok;

        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            Resolution(); ThemeJson(); Setting(); TextAccent(); Contrast(); Dictionaries(); HudPalette();
        }

        static void Resolution()
        {
            var sysLight = new FakeSystemTheme { Light = true }; var sysDark = new FakeSystemTheme { Light = false }; var sysNone = new FakeSystemTheme { Light = null };
            Ok(!Mode.Resolve("console", "follow", null, sysLight), "theme.json has no mode: dark (today's look), even if Windows is light");
            Ok(!Mode.Resolve("console", "follow", "dark", sysLight), "Hallow mode dark: dark");
            Ok(Mode.Resolve("console", "follow", "light", sysDark), "Hallow mode light: light");
            Ok(Mode.Resolve("console", "follow", " LIGHT ", sysDark) && Mode.Resolve("classic", null, "Light", sysDark), "the mode is read case- and space-insensitively; a missing own setting = Follow Hallow");
            Ok(!Mode.Resolve("console", "follow", "sepia", sysLight), "an unknown Hallow mode: dark");
            Ok(Mode.Resolve("console", "follow", "system", sysLight) && sysLight.Reads == 1, "Hallow mode system + Windows light (AppsUseLightTheme = 1): light");
            Ok(!Mode.Resolve("console", "follow", "system", sysDark), "Hallow mode system + Windows dark: dark");
            Ok(!Mode.Resolve("console", "follow", "system", sysNone) && !Mode.Resolve("console", "follow", "system", null), "system, but Windows' value can't be read: dark");
            var r0 = sysLight.Reads;
            Ok(!Mode.Resolve("console", "dark", "light", sysLight) && !Mode.Resolve("classic", "dark", "system", sysLight), "Guard's own Dark wins over Hallow's light / system");
            Ok(Mode.Resolve("console", "light", "dark", sysDark) && Mode.Resolve("classic", "light", null, sysDark), "Guard's own Light wins over Hallow's dark / missing");
            Ok(sysLight.Reads == r0, "with an own choice Windows isn't even asked");
            Ok(!Mode.Resolve("cyberblue", "light", "light", sysLight) && !Mode.Resolve("Cyber blue", "follow", "system", sysLight), "Cyber blue ignores the mode: always dark");
            Ok(Mode.Resolve("classic", "follow", "light", sysDark) && Mode.Resolve("console", "follow", "light", sysDark), "Hallow console and Hallow classic both have a light version");
            Ok(Mode.Own("LIGHT") == "light" && Mode.Own("dark") == "dark" && Mode.Own(null) == "follow" && Mode.Own("system") == "follow" && Mode.Own("x") == "follow", "Guard's own setting: follow / light / dark, anything else = follow");
            Ok(Mode.OwnLabel("follow") == "Follow Hallow" && Mode.OwnLabel("light") == "Light" && Mode.OwnLabel("dark") == "Dark", "the setting's labels");
            Ok(Mode.Why("cyberblue", "light", "light").Contains("always dark") && Mode.Why("console", "light", "dark") == "your choice here" && Mode.Why("console", "follow", "system") == "Hallow follows Windows", "Settings says where the answer came from");
            bool? real = null; bool threw = false; try { real = new RegistrySystemTheme().AppsUseLight(); } catch { threw = true; }
            Ok(!threw, "Windows' real app mode is only read (" + (real == null ? "unknown" : real.Value ? "light" : "dark") + "), never changed");
        }

        // the test theme.json (in the test data folder) - the real %APPDATA%\Hallow\theme.json is never read or written here
        static void ThemeJson()
        {
            Ok(GuardSettings.TestDir != null && Accent.FilePath.StartsWith(GuardSettings.TestDir, StringComparison.OrdinalIgnoreCase), "(theme.json is the test copy, not %APPDATA%\\Hallow)");
            var file = Accent.FilePath; Directory.CreateDirectory(Accent.Folder);
            string backup = File.Exists(file) ? File.ReadAllText(file) : null;
            try
            {
                if (File.Exists(file)) File.Delete(file);
                Ok(Accent.ReadMode() == null && Mode.Hallow(Accent.ReadMode()) == "dark", "no theme.json: no mode -> dark");
                File.WriteAllText(file, "{\"accent\":\"#3399FF\",\"updated\":\"2026-11-21T00:00:00Z\"}");
                Ok(Accent.ReadMode() == null && Accent.Read() == "#3399FF", "a theme.json from before (accent only): no mode -> dark, the accent still read");
                File.WriteAllText(file, "{\"accent\":\"#3399FF\",\"mode\":\"light\",\"updated\":\"x\",\"somethingNew\":{\"a\":1}}");
                Ok(Accent.ReadMode() == "light" && Accent.Read() == "#3399FF", "mode light next to the accent and an unknown field: both read");
                File.WriteAllText(file, "{\"mode\":\"system\"}");
                Ok(Mode.Hallow(Accent.ReadMode()) == "system", "mode system");
                File.WriteAllText(file, "{\"mode\":5}");
                Ok(Accent.ReadMode() == null, "a mode that isn't text: ignored (dark)");
                File.WriteAllText(file, "{broken");
                Ok(Accent.ReadMode() == null && Accent.Read() == null, "a broken file: dark, the own accent - never a crash");
                var before = File.ReadAllText(file);
                Mode.Resolve("console", "follow", Accent.ReadMode(), new FakeSystemTheme());
                Ok(File.ReadAllText(file) == before, "Guard only reads theme.json (Hallow Toolkit owns it)");
            }
            finally
            {
                try { if (backup != null) File.WriteAllText(file, backup); else if (File.Exists(file)) File.Delete(file); } catch { }
            }
        }

        static void Setting()
        {
            var file = Path.Combine(GuardSettings.Dir, "settings.json");
            string backup = File.Exists(file) ? File.ReadAllText(file) : null;
            try
            {
                File.WriteAllText(file, "{\"Look\":\"console\",\"Scans\":[],\"UseHallowAccent\":true}");
                Ok(GuardSettings.Load().Mode == "follow", "1.7 settings (no Mode): Follow Hallow");
                var s = GuardSettings.Load(); s.Mode = "light"; s.Save();
                Ok(File.ReadAllText(file).Contains("\"Mode\":\"light\"") && GuardSettings.Load().Mode == "light", "Light is saved in Guard's own settings and kept");
                File.WriteAllText(file, "{\"Mode\":\"purple\",\"Scans\":[]}");
                Ok(GuardSettings.Load().Mode == "follow", "a junk Mode: Follow Hallow");
                Ok(new GuardSettings().Mode == "follow", "a new install: Follow Hallow");
            }
            finally
            {
                try { if (backup != null) File.WriteAllText(file, backup); else if (File.Exists(file)) File.Delete(file); } catch { }
            }
        }

        static Color Hex(string s) { return (Color)ColorConverter.ConvertFromString(s); }
        static void TextAccent()
        {
            var t = Mode.TextAccent(Accent.Default);
            Ok(Mode.Ratio(t, "#FFFFFF") >= 4.5 && Mode.Ratio(t, Mode.LightBg) >= 4.5, "the default orange darkened for text: " + t + " (" + Mode.Ratio(t, "#FFFFFF").ToString("0.00") + ":1 on white, " + Mode.Ratio(t, Mode.LightBg).ToString("0.00") + ":1 on the page)");
            var c = Hex(t);
            Ok(c.R > c.G && c.G > c.B && c.R >= 0xA0 && c.R <= 0xC0, "it stays orange (about #B85410)");
            Ok(Mode.TextAccent("#3A1F8F") == "#3A1F8F", "an accent that already reads well on light isn't changed");
            foreach (var a in new[] { "#FFD400", "#22E1FF", "#8B5CF6", "#6ED28C", "#FF4FA0" })
            { var x = Mode.TextAccent(a); Ok(Mode.Ratio(x, "#FFFFFF") >= 4.5 && Mode.Ratio(x, Mode.LightBg) >= 4.5, "accent " + a + " -> " + x + " reads on light (>= 4.5:1)"); }
            Ok(Mode.Ratio(Accent.OnAccent(Accent.Default), Accent.Default) >= 4.5, "the filled Accent button keeps the real orange with dark text (" + Mode.Ratio(Accent.OnAccent(Accent.Default), Accent.Default).ToString("0.0") + ":1)");
        }

        // every text / background pair in the light palette
        static void Contrast()
        {
            var bgs = new[] { Mode.LightBg, Mode.LightPanel };
            foreach (var bg in bgs)
            {
                foreach (var fg in new[] { Mode.LightText, Mode.LightMuted, Mode.LightLilac, Mode.LightNav, Mode.LightRed, Mode.LightInfo, Mode.TextAccent(Accent.Default) })
                    Ok(Mode.Ratio(fg, bg) >= 4.5, "light text " + fg + " on " + bg + ": " + Mode.Ratio(fg, bg).ToString("0.00") + ":1 (>= 4.5)");
                foreach (var fg in new[] { Mode.LightGreen, Mode.LightAmber, Mode.LightLow, "#8F87A3" })
                    Ok(Mode.Ratio(fg, bg) >= 3, "light status colour / icon / control " + fg + " on " + bg + ": " + Mode.Ratio(fg, bg).ToString("0.00") + ":1 (>= 3)");
            }
            foreach (var fg in new[] { Mode.LightText, Mode.LightMuted, Mode.LightNav })
                Ok(Mode.Ratio(fg, Mode.LightPanel2) >= 4.5, "light text " + fg + " on the hover / selected " + Mode.LightPanel2 + ": " + Mode.Ratio(fg, Mode.LightPanel2).ToString("0.00") + ":1");
            Ok(Mode.Ratio("#FFFFFF", Mode.TextAccent(Accent.Default)) >= 4.5, "white on the darkened accent (classic's chips)");
            Ok(Mode.Ratio("#FFFFFF", Mode.LightRed) >= 4.5, "white on the light red (badges)");
            Ok(Mode.Ratio("#FFFFFF", Mode.LightGreen) >= 3 && Mode.Ratio("#FFFFFF", Mode.LightAmber) >= 3, "white on the light green / amber badges (bold, >= 3)");
            Ok(Mode.Ratio(Mode.LightText, "#FBFAFD") >= 4.5 && Mode.Ratio(Mode.LightMuted, "#FBFAFD") >= 4.5, "the scan console's text on its light background");
        }

        static string Res(string name) { using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) return s == null ? "" : new StreamReader(s).ReadToEnd(); }
        static string[] Keys(string x) { return Regex.Matches(x, "x:Key=\"([^\"]+)\"").Cast<Match>().Select(m => m.Groups[1].Value).ToArray(); }
        static void Dictionaries()
        {
            foreach (var pair in new[] { Tuple.Create("HallowGuard.Theme.xaml", "Hallow classic", new[] { "#16121C", "#211B2A", "#2E2639", "#3A3248", "#ECE8F4", "#8F88A0", "#2A2333", "#241E2E", "#1A1522" }),
                                         Tuple.Create("HallowGuard.ThemeConsole.xaml", "Hallow console", new[] { "#14101B", "#1C1726", "#221C2E", "#3A3248", "#ECE8F4", "#9790A8", "#1E1829", "#120E18", "#D6D0E2" }) })
            {
                var dark = Res(pair.Item1); var ta = Mode.TextAccent(Accent.Default);
                var light = pair.Item1.Contains("Console") ? Mode.LightConsole(dark, ta) : Mode.LightClassic(dark, ta);
                Ok(dark.Length > 0 && Keys(dark).SequenceEqual(Keys(light)), pair.Item2 + " light: the same resource keys, only the values swap");
                Ok(pair.Item3.All(h => light.IndexOf(h, StringComparison.OrdinalIgnoreCase) < 0), pair.Item2 + " light: none of the dark backgrounds / text colours left");
                Ok(light.Contains("\"" + Mode.LightBg + "\"") && light.Contains("\"" + Mode.LightText + "\"") && light.Contains("\"" + Mode.LightMuted + "\""), pair.Item2 + " light: the family's light background, text and muted text");
                Ok(Regex.Matches(light, "<DropShadowEffect[^>]*>").Cast<Match>().All(m => m.Value.Contains("Opacity=\"0\"")), pair.Item2 + " light: no glows");
                Ok(Regex.IsMatch(light, "Property=\"CaretBrush\" Value=\"" + ta + "\""), pair.Item2 + " light: the caret (thin line) uses the darkened accent");
                Ok(Regex.Matches(light, "#[0-9A-Fa-f]{6}(?:[0-9A-Fa-f]{2})?\\b").Count == Regex.Matches(dark, "#[0-9A-Fa-f]{6}(?:[0-9A-Fa-f]{2})?\\b").Count, pair.Item2 + " light: every colour stays well-formed");
                var withAccent = Accent.ApplyTo(light, "#3399FF");
                Ok(withAccent.IndexOf("F07820", StringComparison.OrdinalIgnoreCase) < 0, pair.Item2 + " light: the theme.json accent still swaps in for the fills");
                Ok(Mode.LightClassic(dark, ta) != dark, "(something changed)");
            }
            var classicLight = Mode.LightClassic(Res("HallowGuard.Theme.xaml"), "#B04F0F");
            Ok(classicLight.Contains("<Setter Property=\"Background\" Value=\"#F07820\"/>"), "Hallow classic light: the Accent button keeps the real accent as its fill");
            Ok(Res("HallowGuard.ThemeCyber.xaml").Contains("#22E1FF"), "(Cyber blue's dictionary is never given a light version)");
        }

        static string H(Brush b) { var c = Hud.C(b); return "#" + c.R.ToString("X2") + c.G.ToString("X2") + c.B.ToString("X2"); }
        static void HudPalette()
        {
            var keepLight = Mode.IsLight; var keepLook = Look.Current;
            try
            {
                Mode.IsLight = true; Look.Current = "console"; Hud.Use("console", Accent.Default);
                Ok(H(Hud.Bg) == "#F6F4FA" && H(Hud.Panel) == "#FFFFFF" && H(Hud.PanelHi) == "#EEEAF5" && H(Hud.Line) == "#DAD3E6", "Hallow console light: background / panel / panel 2 / border from the spec");
                Ok(H(Hud.Text) == "#1E1A26" && H(Hud.Muted) == "#6B6478" && H(Hud.Lilac) == "#7A5CC0", "Hallow console light: text / muted / lilac from the spec");
                Ok(H(Hud.Green) == "#1E8E4F" && H(Hud.Amber) == "#A66A00" && H(Hud.Red) == "#C2333F", "Hallow console light: the light status colours");
                Ok(H(Hud.Glow) == Mode.TextAccent(Accent.Default) && Hud.Ratio(Hud.C(Hud.Glow), Hud.C(Hud.Bg)) >= 4.5, "Hallow console light: the glow is the darkened accent (lines and text read)");
                Ok(Hud.Fx(new System.Windows.Media.Effects.DropShadowEffect()) == null, "Hallow console light: no glow effects");
                Ok(Hud.Ratio(Hud.C(Hud.Text), Hud.C(Hud.CardTop)) >= 4.5 && Hud.Ratio(Hud.C(Hud.Muted), Hud.C(Hud.CardBottom)) >= 4.5 && Hud.Ratio(Hud.C(Hud.Muted), Hud.C(Hud.Console)) >= 4.5, "Hallow console light: text and muted text on the cards and the console");
                Hud.Use("console", "#3399FF");
                Ok(H(Hud.Glow) == Mode.TextAccent("#3399FF"), "Hallow console light: another accent is darkened the same way");
                Look.Current = "classic";
                Ok(H(Ui.Green) == "#1E8E4F" && H(Ui.Amber) == "#A66A00" && H(Ui.Red) == "#C2333F" && H(Ui.OnStatus) == "#FFFFFF", "Hallow classic light: the light status colours, white on the badges");
                Look.Current = "cyberblue"; Hud.Use("cyberblue", Accent.Default);
                Ok(H(Hud.Bg) == "#070B12" && H(Hud.Glow) == "#22E1FF", "Cyber blue: the dark cyan palette, whatever the mode");
                Mode.IsLight = false; Look.Current = "console"; Hud.Use("console", Accent.Default);
                Ok(H(Hud.Bg) == "#14101B" && H(Hud.Glow) == "#F07820" && Hud.Fx(new System.Windows.Media.Effects.DropShadowEffect()) != null, "dark: exactly today's Hallow console (glows included)");
                var tl = TrayColors.For(true); var td = TrayColors.For(false);
                Ok(tl.Back.R == 0xFF && tl.Fore.R == 0x1E && td.Back.R == 0x21 && td.Fore.R == 0xEC, "the tray menu follows: light panel + dark text, or the dark ones");
            }
            finally { Mode.IsLight = keepLight; Look.Current = keepLook; Hud.Use(keepLook, Accent.Default); }
        }
    }
}
