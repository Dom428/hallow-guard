// Hallow Guard v1.6: the Hardening page (both looks) and its part of the Overview. Everything here only reads: buttons open the
// right Windows Security / Settings page, run the read-only admin check of Defender's exclusions, or show the steps.
// Wi-Fi: names, security types and "connects automatically" only - Hallow Guard never reads, shows or logs a Wi-Fi password.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace HallowGuard
{
    public partial class MainWindow
    {
        IEnumerable<Check> HardIds(params string[] ids)
        {
            return (c.HardChecks ?? new List<Check>()).Where(x => ids.Contains(x.Id)).OrderBy(x => Array.IndexOf(ids, x.Id));
        }
        FrameworkElement HardGroup(IEnumerable<Check> checks)
        {
            var l = checks.ToList();
            if (Look.IsHud) return CyGroup(l, false);
            var s = new StackPanel();
            foreach (var ch in l) s.Children.Add(CheckCard(ch));
            return s;
        }

        // ---------------- Hardening
        FrameworkElement HardeningPage()
        {
            var sp = Page("Hardening", "Settings that make Windows harder to attack. Hallow Guard only reads them - the buttons open the right Windows Security or Settings page, or show the steps. Nothing is changed for you.");
            var top = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            var refresh = Ui.Btn(c.HardReading ? "Checking..." : "Check again", () => c.RefreshHardening(), true); refresh.IsEnabled = !c.HardReading; top.Children.Add(refresh);
            top.Children.Add(Ui.Btn("Open Windows Security", () => c.RunFix("windowsdefender://threatsettings"), false, "Opens Virus & threat protection settings"));
            sp.Children.Add(top);
            if (c.HardChecks == null) { sp.Children.Add(Ui.Muted(c.HardReading ? "Reading Defender's settings, remote access, Windows features, accounts and Wi-Fi..." : "Not checked yet.", 12.5)); return sp; }
            var h = c.Hard;
            int bad = c.HardChecks.Count(x => x.State == CheckState.Bad || x.State == CheckState.Warn);
            var sumLine = (c.HardValue ?? 0) + (Look.IsHud ? " / 100" : " of 100") + " - " + (bad == 0 ? "nothing to change." : bad == 1 ? "1 thing worth a look." : bad + " things worth a look.") + " This group takes at most " + HardScore.Cap + " points off the family score.";
            sp.Children.Add(Look.IsHud ? (FrameworkElement)CyLine(c.HardValue == null ? Hud.Muted : Hud.ScoreColor(c.HardValue.Value), "[SCORE]", sumLine) : Ui.T(sumLine, 13.5, true, c.HardValue == null ? null : ScoreBrush(c.HardValue.Value), 8));

            sp.Children.Add(Section("Microsoft Defender settings", "the switches behind Defender's protection"));
            sp.Children.Add(HardGroup(HardIds("pua", "cloud", "samples", "netprot", "asr")));

            sp.Children.Add(Section("Defender exclusions", "places Defender doesn't look"));
            sp.Children.Add(HardGroup(HardIds("exclusions")));
            if (h != null && !h.Mp.ExHidden && h.Exclusions.Count > 0) sp.Children.Add(ExclusionList(h.Exclusions));

            sp.Children.Add(Section("Remote access", "ways someone could reach this PC from elsewhere"));
            sp.Children.Add(HardGroup(HardIds("rdp", "tools")));
            var assist = c.AppChecks == null ? null : c.AppChecks.FirstOrDefault(x => x.Id == "assist");
            sp.Children.Add(Ui.Muted("Hallow Assist: " + (assist == null ? "not looked at yet." : assist.NotInstalled ? "not installed." : assist.Line) + " (It's counted under Hallow apps on the Overview, not here.)", 11.5, 8));

            sp.Children.Add(Section("Old or risky features", "things Windows keeps for old programs"));
            sp.Children.Add(HardGroup(HardIds("smb1", "ps2", "autoplay")));

            sp.Children.Add(Section("Accounts", "who can sign in, and with what rights"));
            sp.Children.Add(HardGroup(HardIds("accounts", "nopassword", "guest", "admins", "adminuac")));

            sp.Children.Add(Section("Wi-Fi", "saved networks and the one you're on"));
            sp.Children.Add(HardGroup(HardIds("wifi", "wifinow")));
            if (h != null && h.Wifi.Count > 0) sp.Children.Add(WifiList(h));
            sp.Children.Add(Ui.Muted("Only network names, their security type and whether they connect by themselves are read. Hallow Guard never reads, shows or saves a Wi-Fi password.", 11.5, 8));

            var pts = "Points (lightly): risky Defender exclusions 4, Remote Desktop without Network Level Authentication 4, SMBv1 3, cloud protection off 3, Guest on 3, admin with UAC on never notify 3; most others 1-2. Information lines never cost points.";
            sp.Children.Add(Ui.Muted(pts, 11.5, 4));
            if (h != null) sp.Children.Add(Ui.Muted("Checked " + Score.Ago(h.When, DateTime.Now) + ". Hallow Guard never changes these settings - the buttons only open Windows' own pages.", 11.5, 0));
            return sp;
        }
        FrameworkElement ExclusionList(List<ExclusionItem> items)
        {
            var s = new StackPanel();
            foreach (var x in items.OrderBy(i => i.Flag == null ? 1 : 0))
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
                var kind = Chip(x.Kind == "path" ? "Folder / file" : x.Kind == "extension" ? "File type" : "Process", x.Flag != null ? (Look.IsHud ? Hud.Red : Ui.Red) : (Look.IsHud ? Hud.Muted : Ui.R("Line")));
                if (!Look.IsHud && x.Flag == null) ((TextBlock)((Border)kind).Child).Foreground = Ui.R("Text");
                kind.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(kind, Dock.Left); row.Children.Add(kind);
                if (x.Flag != null) { var fl = Ui.T(x.Flag, 12, true, Look.IsHud ? Hud.Red : Ui.Red); fl.VerticalAlignment = VerticalAlignment.Center; fl.Margin = new Thickness(10, 0, 0, 0); DockPanel.SetDock(fl, Dock.Right); row.Children.Add(fl); }
                var v = Mono(x.Kind == "extension" ? "." + x.Value.TrimStart('*').TrimStart('.') : x.Value, Ui.R("Text")); v.VerticalAlignment = VerticalAlignment.Center; v.Margin = new Thickness(4, 0, 0, 0);
                row.Children.Add(v);
                s.Children.Add(row);
            }
            s.Children.Add(Ui.Muted("Remove an exclusion in Windows Security > Virus & threat protection > Manage settings > Exclusions (Windows asks for admin).", 11.5, 0));
            return Card(s, 8);
        }
        FrameworkElement WifiList(HardeningFacts h)
        {
            var s = new StackPanel();
            foreach (var w in h.Wifi.OrderBy(x => x.Open && x.AutoConnect ? 0 : x.Open ? 1 : 2).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
            {
                var row = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
                bool risky = w.Open && w.AutoConnect;
                var col = risky ? (Look.IsHud ? Hud.Amber : Ui.Amber) : w.Open || w.Weak ? Ui.R("Muted") : (Look.IsHud ? Hud.Green : Ui.Green);
                var tag = Chip(w.Open ? "Open" : w.Weak ? "Weak" : "Password", risky ? col : w.Open || w.Weak ? (Look.IsHud ? Hud.Muted : Ui.R("Line")) : col);
                if (!Look.IsHud && !risky && (w.Open || w.Weak)) ((TextBlock)((Border)tag).Child).Foreground = Ui.R("Text");
                tag.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(tag, Dock.Left); row.Children.Add(tag);
                var mode = Ui.Muted((w.AutoConnect ? "connects automatically" : "connects when you choose") + (w.Name == h.WifiConnected ? "  -  connected now" : ""), 11.5); mode.VerticalAlignment = VerticalAlignment.Center; mode.Margin = new Thickness(10, 0, 0, 0); DockPanel.SetDock(mode, Dock.Right); row.Children.Add(mode);
                var nm = OneLine(Ui.T(w.Name, 13, true)); nm.VerticalAlignment = VerticalAlignment.Center; nm.Margin = new Thickness(4, 0, 0, 0);
                var sec = Mono("  " + (w.Auth ?? "?") + (string.IsNullOrEmpty(w.Cipher) || w.Cipher == "None" ? "" : " / " + w.Cipher), Ui.R("Muted")); sec.VerticalAlignment = VerticalAlignment.Center; sec.Margin = new Thickness(0);
                var mid = new StackPanel { Orientation = Orientation.Horizontal }; mid.Children.Add(nm); mid.Children.Add(sec);
                row.Children.Add(mid);
                s.Children.Add(row);
            }
            return Card(s, 8);
        }

        // ---------------- the Overview's Hardening part: what's worth a look, and a way to the page
        void HardeningSummary(StackPanel sp)
        {
            if (c.HardChecks == null) return;
            sp.Children.Add(Section("Hardening", c.HardValue + (Look.IsHud ? " / 100" : " of 100")));
            var look = Ordered(c.HardChecks.Where(x => x.State == CheckState.Bad || x.State == CheckState.Warn || x.State == CheckState.Unknown)).ToList();
            if (look.Count == 0) sp.Children.Add(Card(Look.IsHud ? CyLine(Hud.Green, "[OK]", "All " + c.HardChecks.Count + " hardening checks look fine.") : (UIElement)Ui.T("All " + c.HardChecks.Count + " hardening checks look fine.", 13, false, Ui.Green), 8));
            else sp.Children.Add(HardGroup(look));
            var row = new DockPanel { Margin = new Thickness(0, 0, 0, 8) };
            var open = Ui.Btn("Open Hardening", () => Show("hardening")); open.VerticalAlignment = VerticalAlignment.Center; DockPanel.SetDock(open, Dock.Right); row.Children.Add(open);
            int rest = c.HardChecks.Count - look.Count;
            row.Children.Add(Ui.Muted((rest > 0 ? (rest == 1 ? "1 more check looks fine or is just information" : rest + " more checks look fine or are just information") + " - the Hardening page has them all. " : "") + "Defender settings and exclusions, remote access, old features, accounts and Wi-Fi; this group takes at most " + HardScore.Cap + " off the family score.", 11.5, 0));
            sp.Children.Add(row);
        }

        // "Show steps": how to change it yourself (Hallow Guard never does)
        public void ShowSteps(string title, string text)
        {
            MessageBox.Show(this, text, title + " - Hallow Guard", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
