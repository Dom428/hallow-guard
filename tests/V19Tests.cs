// Hallow Guard 1.9 tests: light mode readability. Every light text / background pair Guard actually draws, for several accents
// (Guard's orange, violet, yellow, light cyan, a dark blue): small text >= 4.5:1, icons / thin lines >= 3:1. Hallow console and Hallow
// classic; Cyber blue is dark only. Also the family accent rule (Hallow Toolkit 5.16): darken / fill text / light fill.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows.Media;

namespace HallowGuard.Tests
{
    public static class V19Tests
    {
        static Action<bool, string> Ok;
        static readonly string[] Accents = { "#F07820", "#8B5CF6", "#FACC15", "#67E8F9", "#1E3A8A" };

        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            Rule(); Xaml(); Status(); Hud(); Classic();
        }

        static Color Hex(string s) { return (Color)ColorConverter.ConvertFromString(s); }
        static string ToHex(Color c) { return "#" + c.R.ToString("X2") + c.G.ToString("X2") + c.B.ToString("X2"); }
        // a colour at alpha k over a background (what the screen shows)
        static string Over(string bg, string fg, double k) { return ToHex(HallowGuard.Hud.Mix(Hex(bg), Hex(fg), k)); }
        static double R(string a, string b) { return Mode.Ratio(a, b); }
        static void Pair(string fg, string bg, double min, string what) { Ok(R(fg, bg) >= min, "light " + what + ": " + fg + " on " + bg + " = " + R(fg, bg).ToString("0.00") + ":1 (>= " + min + ")"); }

        // the family rule, value for value as Hallow Toolkit 5.16 computes it (reference values from HallowFamily.ps1's own functions)
        static void Rule()
        {
            var refs = new Dictionary<string, string[]> {   // accent -> { text accent (4.5 on #EEEAF5), fill, text on the fill }
                { "#F07820", new[] { "#A94E0B", "#F07820", "#1E1A26" } },
                { "#8B5CF6", new[] { "#763FF4", "#8452F5", "#FFFFFF" } },
                { "#FACC15", new[] { "#7E6503", "#FACC15", "#1E1A26" } },
                { "#67E8F9", new[] { "#057685", "#67E8F9", "#1E1A26" } },
                { "#1E3A8A", new[] { "#1E3A8A", "#1E3A8A", "#FFFFFF" } } };
            foreach (var kv in refs)
            {
                var a = kv.Key; var r = kv.Value;
                Ok(Mode.TextAccent(a) == r[0], "accent " + a + ": text accent " + Mode.TextAccent(a) + " = Hallow Toolkit's " + r[0]);
                Ok(Mode.LightFill(a) == r[1], "accent " + a + ": light fill " + Mode.LightFill(a) + " = Hallow Toolkit's " + r[1]);
                Ok(Mode.FillText(Mode.LightFill(a)) == r[2], "accent " + a + ": text on the fill " + Mode.FillText(Mode.LightFill(a)) + " = Hallow Toolkit's " + r[2]);
            }
            Ok(Mode.LightFill("#8B5CF6") != "#8B5CF6" && R("#FFFFFF", "#8B5CF6") < 4.5 && R(Accent.OnAccent("#8B5CF6"), "#8B5CF6") < 4.5, "(1.8's violet button: " + Accent.OnAccent("#8B5CF6") + " on #8B5CF6 = " + R(Accent.OnAccent("#8B5CF6"), "#8B5CF6").ToString("0.00") + ":1 - why 1.9 darkens the fill)");
            Ok(Mode.Darken("#8B5CF6", 1.0, "#FFFFFF") == "#8B5CF6", "an accent that already reaches the contrast isn't changed");
            Ok(R(Mode.LilacText, Mode.LightPanel2) >= 4.5 && Mode.LilacText == "#7758BF" && Mode.LilacText == Mode.Darken(Mode.LightLilac, 4.5, Mode.LightPanel2), "lilac text " + Mode.LilacText + " (" + R(Mode.LilacText, Mode.LightPanel2).ToString("0.00") + ":1 on #EEEAF5)");
        }

        static string Res(string name) { using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) return s == null ? "" : new StreamReader(s).ReadToEnd(); }
        // a Setter value inside a named style
        static string StyleBlock(string x, string key) { var m = Regex.Match(x, "<Style x:Key=\"" + key + "\"[\\s\\S]*?</Style>"); return m.Success ? m.Value : ""; }
        static string SetterValue(string block, string prop) { var m = Regex.Match(block, "<Setter Property=\"" + prop + "\" Value=\"(#[0-9A-Fa-f]{6})\"/>"); return m.Success ? m.Groups[1].Value.ToUpperInvariant() : null; }

        // what the light dictionaries really hold, after the accent from theme.json is swapped in (as Program.LoadTheme does)
        static void Xaml()
        {
            foreach (var a in Accents)
            {
                var ta = Mode.TextAccent(a); var fill = Mode.LightFill(a); var ft = Mode.FillText(fill);
                // Hallow classic: the Accent button and the checked filter chip
                var cl = Accent.ApplyTo(Mode.LightClassic(Res("HallowGuard.Theme.xaml"), ta, a), a);
                var acc = StyleBlock(cl, "Accent");
                Ok(SetterValue(acc, "Background") == fill && SetterValue(acc, "Foreground") == ft, "classic light, accent " + a + ": the Accent button is " + ft + " on " + fill + " (" + SetterValue(acc, "Foreground") + " on " + SetterValue(acc, "Background") + ")");
                var chip = StyleBlock(cl, "Chip");
                Ok(chip.Contains("x:Key=\"CheckedBg\" Color=\"" + fill + "\"") && chip.Contains("Value=\"" + ft + "\""), "classic light, accent " + a + ": a checked chip is " + ft + " on " + fill);
                // the hover / pressed wash over the fill (#7A5CC0 at 7% / 14%)
                foreach (var k in new[] { 0.0, 0.07, 0.14 }) Pair(ft, Over(fill, "#7A5CC0", k), 4.5, "classic Accent button text (accent " + a + (k > 0 ? ", hover/pressed " + k : "") + ")");
                Ok(Regex.IsMatch(cl, "Property=\"CaretBrush\" Value=\"" + ta + "\""), "classic light, accent " + a + ": caret / focus border in the text accent");

                // Hallow console: the Accent button is filled in light; the open page in the list sits on #EEEAF5
                var co = Accent.ApplyTo(Mode.LightConsole(Res("HallowGuard.ThemeConsole.xaml"), ta, a), a);
                var cacc = StyleBlock(co, "Accent");
                Ok(Regex.Matches(cacc, "<GradientStop Color=\"" + fill + "\"").Count == 2 && SetterValue(cacc, "Foreground") == ft, "console light, accent " + a + ": the Accent button is " + ft + " on " + fill);
                foreach (var k in new[] { 0.0, 0.08, 0.16 }) Pair(ft, Over(fill, "#7A5CC0", k), 4.5, "console Accent button text (accent " + a + (k > 0 ? ", hover/pressed " + k : "") + ")");
                var nav = StyleBlock(co, "Nav");
                Ok(nav.Contains("<GradientStop Color=\"" + Mode.LightPanel2 + "\" Offset=\"0\"/>") && !Regex.IsMatch(nav, "GradientStop Color=\"#[0-9A-Fa-f]{2}" + a.Substring(1) + "\""), "console light, accent " + a + ": the open page is #EEEAF5 (no accent wash under its text)");
                Pair(ta, Mode.LightPanel2, 3, "console open-page bar / focus outline (accent " + a + ")");
                Ok(!Regex.IsMatch(co + cl, "\\{(FILL|FILLTEXT|PANEL2|PANEL2HEX|GREENTEXT)\\}"), "light dictionaries, accent " + a + ": no placeholder left");

                // the accent as text: headings, HALLOW, codes, links - on every light surface (page, panel, card, hover, console)
                foreach (var bg in new[] { "#FFFFFF", Mode.LightBg, Mode.LightPanel2, "#FCFBFE", "#FBFAFD" })
                    Pair(ta, bg, 4.5, "accent text (accent " + a + ")");
                // classic: a "New" chip in the accent with its text
                Pair(Mode.FillText(ta), ta, 4.5, "classic accent chip text (accent " + a + ")");
                // a checked console toggle: the text on the accent wash (#40 = 25%)
                Pair(Mode.LightText, Over("#FFFFFF", a, 0.25), 4.5, "console checked toggle text (accent " + a + ")");
                Pair(Mode.LightText, Over("#FFFFFF", a, 0.25 + 0.75 * 0.16), 4.5, "console checked toggle text, pressed (accent " + a + ")");
            }
            var c2 = Mode.LightConsole(Res("HallowGuard.ThemeConsole.xaml"), Mode.TextAccent(Accent.Default));
            Ok(c2.Contains("<Setter TargetName=\"word\" Property=\"Foreground\" Value=\"" + Mode.LightGreenText + "\"/>"), "console light: the switch's ON word in the status-text green");
            Pair(Mode.LightGreenText, "#DDF1E5", 4.5, "switch ON word on its green track");
            Pair(Mode.LightMuted, Mode.LightPanel, 4.5, "switch OFF word on its track");
        }

        // status colours as text and icons on the light surfaces, and on their own see-through tag / number-box tints
        static void Status()
        {
            var surfaces = new[] { "#FFFFFF", Mode.LightBg, "#FCFBFE", "#FBFAFD", Over("#FBFAFD", Mode.LilacText, 0.12 * 0.35) };
            foreach (var fg in new[] { Mode.LightGreenText, Mode.LightAmberText, Mode.LightRed, Mode.LilacText, Mode.LightMuted, Mode.LightText, Mode.LightInfo })
            {
                foreach (var bg in surfaces) Pair(fg, bg, 4.5, "status / secondary text");
                foreach (var bg in new[] { "#FFFFFF", "#FCFBFE" }) foreach (var k in new[] { 0.08, 0.10 }) Pair(fg, Over(bg, fg, k), 4.5, "tag (10%) / number-box (light 8%) text on its own " + (int)Math.Round(k * 100) + "% tint");
            }
            foreach (var fg in new[] { Mode.LilacText, Mode.LightMuted, Mode.LightText, Mode.LightNav }) Pair(fg, Mode.LightPanel2, 4.5, "nav / hover text");
            foreach (var fg in new[] { Mode.LightGreen, Mode.LightAmber, Mode.LightRed, Mode.LightGreenText, Mode.LightAmberText }) Pair(fg, Mode.LightBg, 3, "status icon / LED");
        }

        static string H(System.Windows.Media.Brush b) { return HallowGuard.Hud.HexOf(b); }
        static void Hud()
        {
            var keepLight = Mode.IsLight; var keepLook = Look.Current;
            try
            {
                Mode.IsLight = true; Look.Current = "console";
                foreach (var a in Accents)
                {
                    HallowGuard.Hud.Use("console", a);
                    Ok(H(HallowGuard.Hud.Glow) == Mode.TextAccent(a), "console light, accent " + a + ": the glow (headings, bars) is the text accent");
                    foreach (var bg in new[] { HallowGuard.Hud.Panel, HallowGuard.Hud.Bg, HallowGuard.Hud.PanelHi, HallowGuard.Hud.CardTop, HallowGuard.Hud.CardBottom, HallowGuard.Hud.Console, HallowGuard.Hud.Side })
                        foreach (var fg in new[] { HallowGuard.Hud.Glow, HallowGuard.Hud.Lilac, HallowGuard.Hud.Muted, HallowGuard.Hud.Text, HallowGuard.Hud.Green, HallowGuard.Hud.Amber, HallowGuard.Hud.Red, HallowGuard.Hud.Info })
                            Pair(H(fg), H(bg), 4.5, "console text (accent " + a + ")");
                }
                Ok(H(HallowGuard.Hud.Green) == Mode.LightGreenText && H(HallowGuard.Hud.Amber) == Mode.LightAmberText && H(HallowGuard.Hud.Lilac) == Mode.LilacText, "console light: status and lilac in their text values");
                Ok(HallowGuard.Hud.Soft(HallowGuard.Hud.Lilac, 0.6).Color.A == 255, "console light: see-through text (nav numbers, IDs, codes) is solid");
                Mode.IsLight = false; HallowGuard.Hud.Use("console", Accent.Default);
                Ok(HallowGuard.Hud.Soft(HallowGuard.Hud.Lilac, 0.6).Color.A == 153 && H(HallowGuard.Hud.Green) == "#6ED28C", "dark: unchanged (see-through text, the dark status colours)");
                Look.Current = "cyberblue"; Mode.IsLight = false; HallowGuard.Hud.Use("cyberblue", Accent.Default);
                Ok(H(HallowGuard.Hud.Lilac) == "#22E1FF", "Cyber blue: untouched");
            }
            finally { Mode.IsLight = keepLight; Look.Current = keepLook; HallowGuard.Hud.Use(keepLook, Accent.Default); }
        }

        // Hallow classic in light: status text, chips (dark or white text, whichever reads), the to-do number circles
        static void Classic()
        {
            var keepLight = Mode.IsLight; var keepLook = Look.Current;
            try
            {
                Mode.IsLight = true; Look.Current = "classic";
                Ok(H(Ui.Green) == Mode.LightGreenText && H(Ui.Amber) == Mode.LightAmberText && H(Ui.Red) == Mode.LightRed, "classic light: status colours in their text values");
                foreach (var c in new[] { Ui.Green, Ui.Amber, Ui.Red, Ui.Info, Ui.Low })
                {
                    foreach (var bg in new[] { "#FFFFFF", Mode.LightBg }) Pair(H(c), bg, 4.5, "classic status text (scores, codes)");
                    Pair(Mode.FillText(H(c)), H(c), 4.5, "classic chip text");
                    Pair(H(Ui.OnStatus), H(c), 4.5, "classic to-do number on its circle");
                }
                foreach (var c in new[] { Mode.LightMuted, Mode.LightLine }) Pair(Mode.FillText(c), c, 4.5, "classic grey chip text");
                foreach (var a in Accents) { var ta = Mode.TextAccent(a); Pair(ta, "#E4DCF3", 3, "classic open page: accent icon/line on #E4DCF3 (accent " + a + ")"); }
                Pair(Mode.LightText, "#E4DCF3", 4.5, "classic open page text");
                foreach (var fg in new[] { Mode.LightText, Mode.LightMuted }) Pair(fg, Mode.LightPanel2, 4.5, "classic button / hover text");
            }
            finally { Mode.IsLight = keepLight; Look.Current = keepLook; }
        }
    }
}
