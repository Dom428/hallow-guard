// Hallow Guard 1.7 tests: the looks' names and the settings migration (a saved 1.4-1.6 "cyber" becomes "Hallow console", "classic"
// stays, "cyberblue" stays), the Hallow console palette (the family's backgrounds and status colours, the Hallow accent as the glow,
// following theme.json) and the Hallow console theme file (the accent is swapped in, also in its see-through forms).
using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Text.RegularExpressions;

namespace HallowGuard.Tests
{
    public static class V17Tests
    {
        static Action<bool, string> Ok;

        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            Names(); Migration(); Palette(); ThemeFile();
        }

        static void Names()
        {
            Ok(Look.Normalize("cyber") == "console" && Look.Normalize("Cyber") == "console" && Look.Normalize(" CYBER ") == "console", "a saved 1.4-1.6 \"cyber\" becomes Hallow console");
            Ok(Look.Normalize("classic") == "classic" && Look.Normalize("Classic") == "classic", "classic stays classic");
            Ok(Look.Normalize("cyberblue") == "cyberblue" && Look.Normalize("Cyber blue") == "cyberblue" && Look.Normalize("cyber-blue") == "cyberblue", "cyberblue stays Cyber blue");
            Ok(Look.Normalize("console") == "console" && Look.Normalize(null) == "console" && Look.Normalize("plaid") == "console", "console, nothing or junk: Hallow console");
            Ok(Look.Label("console") == "Hallow console" && Look.Label("classic") == "Hallow classic" && Look.Label("cyberblue") == "Cyber blue" && Look.Label("cyber") == "Hallow console", "the looks' names in Settings");
            var keep = Look.Current;
            try
            {
                Look.Current = "console"; bool a = Look.IsHud && !Look.IsCyberBlue;
                Look.Current = "cyberblue"; bool b = Look.IsHud && Look.IsCyberBlue;
                Look.Current = "classic"; bool c = !Look.IsHud && !Look.IsCyberBlue;
                Ok(a && b && c, "Hallow console and Cyber blue use the HUD layout; Hallow classic doesn't");
            }
            finally { Look.Current = keep; }
        }

        // the settings file, in the test data folder (never the real one)
        static void Migration()
        {
            var dir = GuardSettings.Dir; var file = Path.Combine(dir, "settings.json");
            Ok(GuardSettings.TestDir != null && dir == GuardSettings.TestDir, "(the test data folder is used, not %APPDATA%)");
            string backup = File.Exists(file) ? File.ReadAllText(file) : null;
            try
            {
                // a 1.6 file as 1.6 wrote it: Look = cyber next to other settings
                File.WriteAllText(file, "{\"AwayEvery\":\"daily\",\"AwayScan\":true,\"Look\":\"cyber\",\"ReportNotify\":false,\"Scans\":[],\"UseHallowAccent\":true,\"UseHallowIcon\":false,\"WatchDownloads\":true}");
                var s = GuardSettings.Load();
                Ok(s.Look == "console", "1.6 settings with Look = cyber: loaded as Hallow console");
                Ok(s.AwayScan && s.AwayEvery == "daily" && !s.ReportNotify && s.WatchDownloads && !s.UseHallowIcon, "the other settings in that file are kept");
                s.Save();
                var text = File.ReadAllText(file);
                Ok(text.Contains("\"Look\":\"console\"") && !text.Contains("\"Look\":\"cyber\""), "saved again: the file says console");
                Ok(GuardSettings.Load().Look == "console", "and stays Hallow console after that");
                File.WriteAllText(file, "{\"Look\":\"classic\",\"Scans\":[]}");
                Ok(GuardSettings.Load().Look == "classic", "1.6 settings with Look = classic: still Hallow classic");
                var cb = GuardSettings.Load(); cb.Look = "cyberblue"; cb.Save();
                Ok(File.ReadAllText(file).Contains("\"Look\":\"cyberblue\"") && GuardSettings.Load().Look == "cyberblue", "choosing Cyber blue is saved and kept (it is never migrated)");
                File.WriteAllText(file, "{\"UseHallowIcon\":true,\"Scans\":[]}");
                Ok(GuardSettings.Load().Look == "console", "a file from before 1.4 (no Look): Hallow console");
                using (var m = new MemoryStream(Encoding.UTF8.GetBytes("{\"Look\":\"cyber\"}")))
                    Ok(((GuardSettings)new DataContractJsonSerializer(typeof(GuardSettings)).ReadObject(m)).Look == "cyber", "(the raw file value is read as-is; Load() does the migration)");
            }
            finally
            {
                try { if (backup != null) File.WriteAllText(file, backup); else if (File.Exists(file)) File.Delete(file); } catch { }
            }
        }

        static string H(System.Windows.Media.Brush b) { var c = Hud.C(b); return "#" + c.R.ToString("X2") + c.G.ToString("X2") + c.B.ToString("X2"); }
        static void Palette()
        {
            try
            {
                Hud.Use("console", Accent.Default);
                Ok(H(Hud.Glow) == "#F07820" && Hud.GlowHex == "#F07820", "Hallow console: the glow is the Hallow orange by default");
                Ok(new[] { Hud.Bg, Hud.Panel, Hud.PanelHi, Hud.Console, Hud.Side, Hud.Dim }.All(b => { var c = Hud.C(b); return c.R < 0x30 && c.G < 0x2A && c.B < 0x42 && c.B > c.G && c.R > c.G; }), "Hallow console: backgrounds are the family's dark purple-black (no blue-black)");
                Ok(H(Hud.Bg) == "#14101B" && H(Hud.Line) == "#3A3248" && H(Hud.Text) == "#ECE8F4", "Hallow console: the family's background, line and text colours");
                Ok(H(Hud.Green) == "#6ED28C" && H(Hud.Amber) == "#F0BE5A" && H(Hud.Red) == "#E05A64", "Hallow console: the family's green / amber / red (no neon)");
                Ok(H(Hud.Lilac) == "#A98BE0", "Hallow console: lilac secondaries");
                Look.Current = "console";
                Ok(H(Ui.Green) == "#6ED28C" && H(Ui.Red) == "#E05A64" && H(Ui.Hi) == "#F07820", "Hallow console: the shared status colours and highlight follow it");
                Hud.Use("console", "#3399FF");
                Ok(H(Hud.Glow) == "#3399FF", "another Hallow accent (theme.json): the glow follows it");
                Hud.Use("console", "#200040");
                Ok(H(Hud.Glow) != "#200040" && Hud.Ratio(Hud.C(Hud.Glow), Hud.C(Hud.PanelHi)) >= 4.5, "a very dark accent is lightened so it still reads (>= 4.5:1)");
                Hud.Use("console", "nonsense");
                Ok(H(Hud.Glow) == "#F07820", "a broken accent: the Hallow orange");
                Hud.Use("cyberblue", "#3399FF");
                Ok(H(Hud.Glow) == "#22E1FF" && H(Hud.Bg) == "#070B12" && H(Hud.Green) == "#39FF88", "Cyber blue: the 1.4 cyan look, whatever the accent");
            }
            finally { Look.Current = "console"; Hud.Use("console", Accent.Default); }
        }

        static void ThemeFile()
        {
            string x; using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("HallowGuard.ThemeConsole.xaml")) x = s == null ? null : new StreamReader(s).ReadToEnd();
            Ok(x != null && x.Contains("x:Key=\"Nav\"") && x.Contains("FocusVisualStyleKey") && x.Contains("x:Key=\"Accent\"") && x.Contains("x:Key=\"Switch\""), "Hallow console theme: nav, buttons, switches and a focus outline");
            Ok(x != null && x.IndexOf("22E1FF", StringComparison.OrdinalIgnoreCase) < 0 && x.IndexOf("#070B12", StringComparison.OrdinalIgnoreCase) < 0 && x.IndexOf("#39FF88", StringComparison.OrdinalIgnoreCase) < 0, "Hallow console theme: no cyan, blue-black or neon green");
            Ok(x != null && x.Contains("#14101B") && x.Contains("#F07820"), "Hallow console theme: the family background and the Hallow accent");
            var swapped = x == null ? "" : Accent.ApplyTo(x, "#3399FF");
            Ok(swapped.IndexOf("F07820", StringComparison.OrdinalIgnoreCase) < 0 && swapped.Contains("#3399FF") && swapped.Contains("#333399FF"), "the theme.json accent is swapped in everywhere, see-through forms included");
            Ok(Regex.Matches(swapped, "#[0-9A-Fa-f]{6}(?:[0-9A-Fa-f]{2})?\\b").Count == Regex.Matches(x ?? "", "#[0-9A-Fa-f]{6}(?:[0-9A-Fa-f]{2})?\\b").Count, "the swap keeps every colour well-formed");
            var classic = Accent.ApplyTo("<a C=\"#F07820\"/>", "#3399FF");
            Ok(classic == "<a C=\"#3399FF\"/>", "the classic theme's accent swap is unchanged");
        }
    }
}
