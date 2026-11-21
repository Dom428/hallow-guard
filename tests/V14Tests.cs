// Hallow Guard 1.4 tests: the Look setting (default, saved and loaded, old and broken files), the animation gate with a fake
// window and a fake "game running" source (pauses when hidden, minimized, not in front, during a game or full-screen app and
// when Windows' animations are off; never asks about games when nothing animates), the scan console's lines, the status codes
// (never colour alone) and the cyber colours' contrast.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Windows.Media;

namespace HallowGuard.Tests
{
    public static class V14Tests
    {
        static Action<bool, string> Ok;

        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            LookSetting(); Gate(); Console(); Codes(); Contrast(); ThemeFile();
        }

        // ---------------- Settings > Look
        static void LookSetting()
        {
            // v1.7: the default is "console" (Hallow console); a 1.4-1.6 "cyber" becomes it (see V17Tests for the migration)
            Ok(Look.Normalize(null) == "console" && Look.Normalize("") == "console" && Look.Normalize("neon") == "console" && Look.Normalize(" Classic ") == "classic" && Look.Normalize("cyber") == "console", "look names: classic, anything else is the default (console)");
            Ok(new GuardSettings().Look == "console", "a new install: the Hallow console look");
            var old = "{\"UseHallowIcon\":true,\"AwayScan\":true,\"Scans\":[]}";
            using (var m = new MemoryStream(Encoding.UTF8.GetBytes(old)))
                Ok(((GuardSettings)new DataContractJsonSerializer(typeof(GuardSettings)).ReadObject(m)).Look == "console", "a 1.3 settings file (no Look): the Hallow console look");
            // saved and loaded from the test data folder (never the real one)
            var dir = GuardSettings.Dir; var file = Path.Combine(dir, "settings.json");
            Ok(GuardSettings.TestDir != null && dir == GuardSettings.TestDir, "(the test data folder is used, not %APPDATA%)");
            string backup = File.Exists(file) ? File.ReadAllText(file) : null;
            try
            {
                var s = GuardSettings.Load(); s.Look = "classic"; s.Save();
                Ok(File.ReadAllText(file).Contains("\"Look\":\"classic\"") && GuardSettings.Load().Look == "classic", "Look = classic is saved and loaded");
                var l = GuardSettings.Load(); l.Look = "console"; l.Save();
                Ok(GuardSettings.Load().Look == "console", "switching back to Hallow console is saved");
                File.WriteAllText(file, "{\"Look\":\"plaid\",\"Scans\":[]}");
                Ok(GuardSettings.Load().Look == "console", "an unknown look in the file: Hallow console");
                File.WriteAllText(file, "{\"Look\":null,\"Scans\":[]}");
                Ok(GuardSettings.Load().Look == "console", "Look = null in the file: Hallow console");
                var keep = GuardSettings.Load(); keep.Look = "classic"; keep.AwayScan = true; keep.WatchDownloads = true; keep.Save();
                var back = GuardSettings.Load();
                Ok(back.Look == "classic" && back.AwayScan && back.WatchDownloads, "the look is saved next to the other settings without touching them");
                GuardSettings.Frozen = true; var fz = GuardSettings.Load(); fz.Look = "console"; fz.Save(); GuardSettings.Frozen = false;
                Ok(GuardSettings.Load().Look == "classic", "--snap (frozen settings) never saves the look");
            }
            finally
            {
                GuardSettings.Frozen = false;
                try { if (backup != null) File.WriteAllText(file, backup); else if (File.Exists(file)) File.Delete(file); } catch { }
            }
        }

        // ---------------- the animation gate (fake window, fake game)
        static void Gate()
        {
            var view = new FakeView(); var game = new FakeBusy(); bool sys = true;
            var g = new AnimGate(view, game, () => sys) { BusyCache = TimeSpan.Zero };
            Ok(!g.Update() && g.Why == "nothing to animate" && g.BusyChecks == 0, "nothing on the page animates: not running, no game check at all");
            var calls = new List<bool>(); g.Add(calls.Add);
            Ok(calls.Count == 1 && !calls[0], "a part added while paused gets the still frame");
            Ok(g.Update() && g.Running && g.Why == null && calls.Last() && g.BusyChecks == 1, "visible, in front, no game, animations on: running");
            int n = calls.Count; g.Update(); g.Update();
            Ok(calls.Count == n, "no change: the parts aren't told again");
            view.Minimized = true; int bc = g.BusyChecks;
            Ok(!g.Update() && g.Why == "minimized" && !calls.Last() && g.BusyChecks == bc, "minimized: paused (and no game check)");
            view.Minimized = false; view.Visible = false;
            Ok(!g.Update() && g.Why == "hidden" && g.BusyChecks == bc, "hidden (closed to the tray): paused");
            view.Visible = true; view.Focused = false;
            Ok(!g.Update() && g.Why == "not focused" && g.BusyChecks == bc, "another window in front: paused");
            view.Focused = true; game.Value = "a game is running";
            Ok(!g.Update() && g.Why == "a game is running" && !calls.Last(), "a game is running: paused");
            game.Value = "a full-screen app is open";
            Ok(!g.Update() && g.Why == "a full-screen app is open", "a full-screen app: paused");
            game.Value = null; sys = false; bc = g.BusyChecks;
            Ok(!g.Update() && g.Why == "Windows animations are off" && g.BusyChecks == bc, "Windows' Show animations off: paused");
            sys = true;
            Ok(g.Update() && calls.Last(), "everything fine again: running again");
            var late = new List<bool>(); g.Add(late.Add);
            Ok(late.Count == 1 && late[0], "a part added while running starts at once");
            g.Clear();
            Ok(g.Parts == 0 && !calls.Last() && !late.Last(), "a new page: the old parts are stopped and forgotten");
            bc = g.BusyChecks;
            Ok(!g.Update() && g.BusyChecks == bc, "after that, nothing animates: no game check");
            // the game check is cached (it looks at processes)
            var g2 = new AnimGate(new FakeView(), game, () => true) { BusyCache = TimeSpan.FromSeconds(30) }; g2.Add(x => { });
            g2.Update(); g2.Update(); g2.Update();
            Ok(g2.BusyChecks == 1, "the game check is asked at most once per BusyCache");
            game.Value = "a game is running"; g2.ForgetBusy();
            Ok(!g2.Update() && g2.BusyChecks == 2, "ForgetBusy asks again");
            game.Value = null;
            var g3 = new AnimGate(new FakeView(), game, () => true) { Disabled = true }; var sn = new List<bool>(); g3.Add(sn.Add);
            Ok(!g3.Update() && g3.Why == "snapshot" && sn.All(x => !x) && g3.BusyChecks == 0, "--snap: always the still frame");
            var g4 = new AnimGate(new FakeView(), new ThrowingBusy(), () => { throw new Exception("x"); }); g4.Add(x => { throw new Exception("part"); });
            bool okay = true; try { g4.Update(); g4.Clear(); } catch { okay = false; }
            Ok(okay, "a failing source or part never breaks the window");
            Ok(AnimGate.Reason(true, false, true, true, () => null) == null && AnimGate.Reason(false, true, false, false, () => "game") == "hidden", "the reasons, in order");
        }
        class ThrowingBusy : IBusySource { public string Busy() { throw new InvalidOperationException(); } }

        // ---------------- the scan console
        static void Console()
        {
            var start = new DateTime(2026, 11, 20, 21, 0, 0);
            var j = new ScanJob(@"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3002-0\MpCmdRun.exe", "full", null) { Start = start };
            j.Lines.Add("Scan starting..."); j.Times.Add(start.AddSeconds(1)); j.Lines.Add(""); j.Times.Add(start.AddSeconds(2));
            var l = MainWindow.ConsoleLines(j, start.AddMinutes(9).AddSeconds(5));
            Ok(l[0].Item2 == "GUARD" && l[0].Item3.Contains("MpCmdRun.exe") && l[0].Item3.Contains("4.18.25090.3002") && l[1].Item3.Contains("-Scan -ScanType 2"), "console: the engine and the exact MpCmdRun arguments first");
            Ok(l.Count(x => x.Item2 == "DEFENDER") == 1 && l.Any(x => x.Item2 == "DEFENDER" && x.Item3 == "Scan starting..." && x.Item1 == start.AddSeconds(1)), "console: MpCmdRun's lines with the time they came (empty ones left out)");
            var beats = l.Where(x => x.Item3.StartsWith("scanner still running")).ToList();
            Ok(beats.Count == 6 && beats.Last().Item3.EndsWith("00:09:00") && beats.First().Item3.EndsWith("00:04:00"), "console: a heartbeat a minute, the last six");
            Ok(l.Zip(l.Skip(1), (a, b) => a.Item1 <= b.Item1).All(x => x), "console: in time order");
            var away = new ScanJob(null, "quick", null) { Start = start, Low = true };
            var la = MainWindow.ConsoleLines(away, start.AddSeconds(20));
            Ok(la.Any(x => x.Item3.StartsWith("priority idle")) && !la.Any(x => x.Item3.StartsWith("scanner still")), "console: the away scan says it runs at idle priority; no heartbeat in the first minute");
            var cu = new ScanJob(null, "custom", @"D:\Old games") { Start = start };
            Ok(MainWindow.ConsoleLines(cu, start)[1].Item3.Contains("-ScanType 3 -File \"D:\\Old games\""), "console: a folder scan shows the folder");
        }

        // ---------------- nothing by colour alone
        static void Codes()
        {
            var states = (CheckState[])Enum.GetValues(typeof(CheckState));
            var codes = states.Select(s => Hud.Code(s)).ToList();
            Ok(codes.Distinct().Count() == states.Length && Hud.Code(CheckState.Good) == "[OK]" && Hud.Code(CheckState.Warn) == "[WARN]" && Hud.Code(CheckState.Bad) == "[RISK]", "each state has its own code: [OK] [WARN] [RISK] ...");
            Ok(Hud.Code(CheckState.Good, true) == "[N/A]", "a Hallow app that isn't installed: [N/A]");
            Ok(Hud.Status(100) == "SECURE" && Hud.Status(90) == "SECURE" && Hud.Status(89) == "ATTENTION" && Hud.Status(70) == "ATTENTION" && Hud.Status(69) == "AT RISK" && Hud.Status(-1) == "SCANNING", "status readout: SECURE / ATTENTION / AT RISK at the score colours' limits");
            Ok(Hud.Spaced("To do").Replace("\u200A", "").Replace("\u2002", " ") == "TO DO", "spaced headings are the same words in capitals");
        }

        // ---------------- text contrast >= 4.5:1 on the panels and the background
        static double Lum(Color c)
        {
            Func<byte, double> f = v => { var x = v / 255.0; return x <= 0.03928 ? x / 12.92 : Math.Pow((x + 0.055) / 1.055, 2.4); };
            return 0.2126 * f(c.R) + 0.7152 * f(c.G) + 0.0722 * f(c.B);
        }
        static double Ratio(Brush a, Brush b) { double x = Lum(Hud.C(a)), y = Lum(Hud.C(b)); return (Math.Max(x, y) + 0.05) / (Math.Min(x, y) + 0.05); }
        // v1.7: every HUD palette - Hallow console with the default orange and with other accents (a dark one is lightened), and Cyber blue
        public static double Worst()
        {
            var fgs = new[] { Hud.Text, Hud.Muted, Hud.Glow, Hud.Lilac, Hud.Green, Hud.Amber, Hud.Red, Hud.Info, Hud.Low };
            var bgs = new[] { Hud.Bg, Hud.Panel, Hud.PanelHi, Hud.Console, Hud.Side, Hud.Well, Hud.CardTop, Hud.CardBottom };
            return fgs.SelectMany(f => bgs.Select(b => Ratio(f, b))).Min();
        }
        static void Contrast()
        {
            try
            {
                foreach (var t in new[] { Tuple.Create("console", "#F07820"), Tuple.Create("console", "#A98BE0"), Tuple.Create("console", "#3050A0"), Tuple.Create("console", "#200040"), Tuple.Create("console", "#00FF66"), Tuple.Create("cyberblue", "#F07820") })
                {
                    Hud.Use(t.Item1, t.Item2); double worst = Worst();
                    Ok(worst >= 4.5, t.Item1 + " text colours (accent " + t.Item2 + ") on every background: contrast >= 4.5:1 (worst " + worst.ToString("0.0") + ")");
                }
            }
            finally { Hud.Use(Look.ConsoleName, Accent.Default); }
        }

        // ---------------- the Cyber blue theme never gets the classic accent swapped into it
        static void ThemeFile()
        {
            string x; using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("HallowGuard.ThemeCyber.xaml")) x = s == null ? null : new StreamReader(s).ReadToEnd();
            Ok(x != null && x.Contains("x:Key=\"Nav\"") && x.Contains("FocusVisualStyleKey") && x.Contains("x:Key=\"Accent\"") && x.Contains("x:Key=\"Switch\""), "cyber theme: nav, buttons, switches and a neon focus outline");
            Ok(x != null && x.IndexOf("#F07820", StringComparison.OrdinalIgnoreCase) < 0 && x.IndexOf("#F59A50", StringComparison.OrdinalIgnoreCase) < 0 && x.IndexOf("#1A0E04", StringComparison.OrdinalIgnoreCase) < 0, "cyber theme: none of the colours the Hallow accent replaces");
        }
    }
}
