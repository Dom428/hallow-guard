// Hallow Guard v1.2 pages: Network (connections, listeners, firewall), Extensions (risk per browser extension) and Ransomware
// (Controlled folder access). Everything here only reads; buttons open a file's folder, ask Defender to scan, or open the right
// Windows Security / browser page.
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
        static FrameworkElement IconRow(string icon, Brush color, string title, double size = 14)
        {
            var h = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
            var ic = Icons.Make(icon, size + 3, color); ic.Margin = new Thickness(0, 0, 9, 0); ic.VerticalAlignment = VerticalAlignment.Center; h.Children.Add(ic);
            var t = Ui.T(title, size, true); t.VerticalAlignment = VerticalAlignment.Center; h.Children.Add(t);
            return h;
        }
        Button ScanButton(string file)
        {
            return Ui.Btn("Scan with Defender", () => { var e = c.StartScan("custom", file); Say(e ?? "Scanning " + System.IO.Path.GetFileName(file) + " - see the Scan page."); });
        }
        static string Plural(int n, string one, string many) { return n + " " + (n == 1 ? one : many); }

        // ---------------- Network
        FrameworkElement NetworkPage()
        {
            var sp = Page("Network", "What's using the network right now, read from Windows' own connection tables. Hallow Guard sends nothing anywhere: it doesn't look up countries, and names only when you click Look up names.");
            var top = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            var refresh = Ui.Btn(c.NetReading ? "Looking..." : "Refresh", () => c.RefreshNetwork(), true); refresh.IsEnabled = !c.NetReading; top.Children.Add(refresh);
            var names = Ui.Btn(c.NamesLooking ? "Looking up..." : "Look up names", () => c.LookUpNames(), false, "Asks your DNS server for the name behind each internet address (reverse DNS). Nothing else is sent."); names.IsEnabled = c.Net != null && !c.NamesLooking; top.Children.Add(names);
            top.Children.Add(Ui.Btn("Open Windows Firewall", () => c.RunFix("windowsdefender://network"), false, "Opens Firewall & network protection in Windows Security"));
            sp.Children.Add(top);
            var n = c.Net;
            if (n == null) { sp.Children.Add(Ui.Muted(c.NetReading ? "Reading the connection tables..." : "Not looked at yet.", 12.5)); return sp; }
            if (n.Error != null) { sp.Children.Add(Card(Ui.T("Couldn't read the connection tables: " + n.Error, 12.5, false, Ui.Amber))); return sp; }
            if (Look.Cyber) sp.Children.Add(NetMap(n));   // v1.4: the connection map (the list stays below)
            // listeners
            var sus = n.Listeners.Count(l => l.V == Verdict.Suspicious);
            sp.Children.Add(Section("Open to the network", Plural(n.Listeners.Count, "program waits", "programs wait") + " for connections from other devices" + (sus > 0 ? " - " + sus + " suspicious" : "")));
            sp.Children.Add(Ui.Muted("Programs listening on this PC's network address (not just inside the PC). Games, chat and media apps do this for voice, LAN play or casting. Windows Firewall decides who can actually reach them." + (n.FirewallRead ? "" : " (Windows Firewall's rules couldn't be read.)"), 12, 10));
            if (n.Listeners.Count == 0) sp.Children.Add(Card(Ui.T("Nothing is waiting for connections from the network.", 13, false, Ui.Green), 8));
            foreach (var l in n.Listeners) sp.Children.Add(ListenerRow(l));
            // apps with connections
            int internet = n.Apps.Count(a => a.Remotes.Count > 0);
            sp.Children.Add(Section("Connected right now", Plural(n.Apps.Count, "app has", "apps have") + " open connections" + (internet > 0 ? ", " + internet + " to the internet" : "")));
            sp.Children.Add(Ui.Muted("Countries aren't shown: that needs an online lookup service, and Hallow Guard never sends your connections anywhere." + (c.Names.Count > 0 ? "" : " Addresses are shown as numbers until you click Look up names."), 12, 10));
            foreach (var a in n.Apps) sp.Children.Add(AppRow(a));
            sp.Children.Add(Ui.Muted("Read " + Score.Ago(n.When, DateTime.Now) + " from " + n.Rows + " connection table entries. Hallow Guard never closes connections or changes firewall rules - use Windows Firewall for that.", 11.5, 0));
            return sp;
        }
        FrameworkElement ListenerRow(Listener l)
        {
            var s = new StackPanel();
            var h = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
            var chip = Chip(l.V == Verdict.KnownGood ? "Known good" : l.V == Verdict.Suspicious ? "Suspicious" : "Unknown", VerdictBrush(l.V)); DockPanel.SetDock(chip, Dock.Left); h.Children.Add(chip);
            var ports = Ui.Muted(string.Join(", ", l.Ports.Take(6)) + (l.Ports.Count > 6 ? " +" + (l.Ports.Count - 6) : ""), 11.5); ports.VerticalAlignment = VerticalAlignment.Center; ports.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(ports, Dock.Right); h.Children.Add(ports);
            var nm = OneLine(Ui.T(l.Name + (l.Pids.Count > 0 && !l.Pids.Contains(4) ? "  (process " + string.Join(", ", l.Pids.Take(3)) + (l.Pids.Count > 3 ? "..." : "") + ")" : ""), 13.5, true)); nm.VerticalAlignment = VerticalAlignment.Center; h.Children.Add(nm);
            s.Children.Add(h);
            s.Children.Add(Ui.Muted(l.Reason, 12.5, 2));
            var fwText = NetView.FirewallText(l.Fw);
            bool open = l.Fw != null && (l.Fw.Public == "allowed" || l.Fw.Public == "off");
            s.Children.Add(Ui.T(fwText + (l.AllNetworks ? "" : " (Only on one network address.)"), 12.5, false, open && l.V != Verdict.KnownGood ? Ui.Amber : Ui.R("Text"), 2));
            if (l.Path != null) s.Children.Add(Mono(l.Path, Ui.R("Muted")));
            var btns = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            if (l.Path != null) btns.Children.Add(Ui.Btn("Open file location", () => Controller.OpenLocation(l.Path)));
            if (l.Path != null && l.Exists && !l.Pids.Contains(4)) btns.Children.Add(ScanButton(l.Path));
            btns.Children.Add(Ui.Btn("Open Windows Firewall", () => c.RunFix("windowsdefender://network")));
            s.Children.Add(btns);
            return Card(s, 8);
        }
        FrameworkElement AppRow(NetApp a)
        {
            var s = new StackPanel();
            var h = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
            var cnt = Ui.Muted(Plural(a.Connections, "connection", "connections"), 11.5); cnt.VerticalAlignment = VerticalAlignment.Center; cnt.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(cnt, Dock.Right); h.Children.Add(cnt);
            var nm = OneLine(Ui.T(a.Name, 13.5, true)); h.Children.Add(nm);
            s.Children.Add(h);
            var parts = new List<string>();
            if (a.Remotes.Count > 0) parts.Add(Plural(a.Remotes.Count, "host", "hosts") + " on the internet");
            if (a.Lan > 0) parts.Add(Plural(a.Lan, "connection", "connections") + " on your local network");
            s.Children.Add(Ui.Muted(parts.Count == 0 ? "Connected inside your network." : string.Join(", ", parts) + ".", 12.5, 3));
            foreach (var ip in a.Remotes.Take(4)) { string name; s.Children.Add(Mono(c.Names.TryGetValue(ip, out name) ? ip + "   " + name : ip, Ui.R("Muted"))); }
            if (a.Remotes.Count > 4) s.Children.Add(Ui.Muted("and " + (a.Remotes.Count - 4) + " more", 11.5, 2));
            if (a.Path != null)
            {
                s.Children.Add(Mono(a.Path, Ui.R("Muted")));
                var btns = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
                btns.Children.Add(Ui.Btn("Open file location", () => Controller.OpenLocation(a.Path)));
                if (Snap.On || System.IO.File.Exists(a.Path)) btns.Children.Add(ScanButton(a.Path));
                s.Children.Add(btns);
            }
            return Card(s, 8);
        }

        // ---------------- Extensions
        static Brush RiskBrush(string r) { return r == "High" ? Ui.Red : r == "Medium" ? Ui.Amber : r == "Low" ? Ui.Green : Ui.B("#7FB2F0"); }
        FrameworkElement ExtensionsPage()
        {
            var sp = Page("Extensions", "Browser extensions can see a lot: some can read every page you open. Hallow Guard reads each extension's permissions in Chrome, Edge, Brave, Opera and Firefox and rates it - it never changes your browsers.");
            var top = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
            var refresh = Ui.Btn(c.ExtReading ? "Looking..." : "Look again", () => c.RefreshExtensions(), true); refresh.IsEnabled = !c.ExtReading; top.Children.Add(refresh);
            sp.Children.Add(top);
            var all = c.Exts;
            if (all == null) { sp.Children.Add(Ui.Muted(c.ExtReading ? "Reading your browsers' extensions..." : "Not looked at yet.", 12.5)); return sp; }
            var sum = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) };
            foreach (var r in new[] { "High", "Medium", "Low", "Known" }) sum.Children.Add(Chip(all.Count(x => x.Risk == r) + " " + r.ToLowerInvariant(), RiskBrush(r)));
            if (c.ExtsAt != null) { var ht = Ui.Muted("Checked " + Score.Ago(c.ExtsAt, DateTime.Now) + ".", 11.5); ht.VerticalAlignment = VerticalAlignment.Center; sum.Children.Add(ht); }
            sp.Children.Add(sum);
            if (all.Count == 0) sp.Children.Add(Card(Ui.T("No browser extensions found.", 13, false, Ui.Green), 8));
            foreach (var e in all) sp.Children.Add(ExtRow(e));
            var how = new StackPanel();
            how.Children.Add(IconRow("circle-info", Ui.B("#7FB2F0"), "How the rating works", 13.5));
            how.Children.Add(Ui.Muted("High: not from the browser's store with access to every site, a developer-tool (debugger) extension on every site, or a lot of sensitive access together. Medium: broad access - normal for ad blockers and password managers, but worth knowing. Low: limited access. Known: Hallow Keys and Hallow Shield, which need every site to fill passwords and block ads. Not updated for a year counts a little too (the date comes from the browser, or the extension's folder when the browser doesn't say).", 12, 4));
            how.Children.Add(Ui.Muted("To remove an extension, open the browser's extensions page and click Remove - Hallow Guard never removes or switches off extensions itself.", 12, 0));
            sp.Children.Add(Card(how, 8));
            return sp;
        }
        FrameworkElement ExtRow(ExtInfo e)
        {
            var s = new StackPanel();
            var h = new DockPanel { Margin = new Thickness(0, 0, 0, 3) };
            var chip = Chip(e.Risk, RiskBrush(e.Risk)); DockPanel.SetDock(chip, Dock.Left); h.Children.Add(chip);
            var where = Ui.Muted(e.Browser + (string.IsNullOrEmpty(e.Profile) ? "" : " (" + e.Profile + ")"), 11.5); where.VerticalAlignment = VerticalAlignment.Center; where.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(where, Dock.Right); h.Children.Add(where);
            var nm = OneLine(Ui.T(e.Name + (string.IsNullOrEmpty(e.Version) ? "" : "  " + e.Version) + (e.Enabled ? "" : "  (switched off)"), 13.5, true)); nm.VerticalAlignment = VerticalAlignment.Center; h.Children.Add(nm);
            s.Children.Add(h);
            foreach (var r in e.Reasons) s.Children.Add(Ui.Muted("• " + r, 12.5, 1));
            var btns = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
            var browser = e.Browser;
            btns.Children.Add(Ui.Btn("Open " + browser + "'s extensions page", () => c.OpenExtensionsPage(browser), false, "Opens " + ExtScan.ExtensionsUrl(browser) + " in " + browser));
            s.Children.Add(btns);
            return Card(s, 8);
        }

        // ---------------- Ransomware protection
        FrameworkElement RansomwarePage()
        {
            var sp = Page("Ransomware protection", "Ransomware is malware that locks (encrypts) your files and asks for money to unlock them. Windows' Controlled folder access stops apps it doesn't trust from changing files in protected folders - your documents, pictures and desktop.");
            var cfa = c.Facts == null ? null : c.Facts.Cfa;
            bool other = c.Facts != null && c.Facts.OtherAv.Count > 0;
            // state
            var st = new StackPanel();
            var head = new DockPanel();
            var open = Ui.Btn("Open Ransomware protection", () => c.RunFix(Ransom.Page), true, "Opens Windows Security > Ransomware protection. Hallow Guard never changes it."); DockPanel.SetDock(open, Dock.Right); open.VerticalAlignment = VerticalAlignment.Top; head.Children.Add(open);
            var chk = c.Checks == null ? null : c.Checks.FirstOrDefault(x => x.Id == "cfa");
            var state = chk == null ? CheckState.Unknown : chk.State;
            var ht = new StackPanel();
            ht.Children.Add(IconRow(StateIcon(state), StateBrush(state), "Controlled folder access: " + (cfa == null ? (c.Facts == null ? "checking..." : "unknown") : Ransom.ModeText(cfa.Mode)), 15));
            if (chk != null) ht.Children.Add(Ui.Muted(chk.Line + (chk.Penalty > 0 ? "  (" + chk.Penalty + " points)" : ""), 12.5, 0));
            head.Children.Add(ht);
            st.Children.Add(head);
            sp.Children.Add(Card(st, 10));
            if (other) { sp.Children.Add(Ui.Muted("With another antivirus in charge, Microsoft Defender's ransomware protection isn't used.", 12, 10)); }
            // the warning
            var w = new StackPanel();
            w.Children.Add(IconRow("triangle-exclamation", Ui.Amber, "It can stop games and apps from saving", 13.5));
            w.Children.Add(Ui.T("When it's on, an app Windows doesn't recognise can't write into a protected folder - that includes games saving into Documents\\My Games or Saved Games, and some launchers, mods and editors. If a game says it couldn't save, or Windows shows \"Unauthorized changes blocked\", open Ransomware protection > Allow an app through Controlled folder access and add the game's .exe. Nothing is lost: the change is just blocked until you allow it.", 12.5, false, null, 0));
            if (Look.Cyber) { var wc = Hud.Card(w, new Thickness(16, 12, 16, 12), 10, Hud.Amber); wc.BorderBrush = Hud.Alpha(Hud.Amber, 0.6); sp.Children.Add(wc); }
            else sp.Children.Add(new Border { Child = w, Background = Ui.R("Panel"), BorderBrush = Ui.Amber, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(16, 12, 16, 12), Margin = new Thickness(0, 0, 0, 10) });
            // folders
            var hints = c.Folders ?? new List<FolderHint>();
            sp.Children.Add(Section("Folders worth protecting", hints.Count(h => h.Status == "suggested") > 0 ? hints.Count(h => h.Status == "suggested") + " to add" : null));
            foreach (var hnt in hints)
            {
                var row = new StackPanel();
                var hd = new DockPanel { Margin = new Thickness(0, 0, 0, 2) };
                var col = hnt.Status == "protected" ? Ui.Green : hnt.Status == "suggested" ? Ui.Amber : hnt.Status == "covered" ? Ui.B("#7FB2F0") : Ui.R("Line");
                var word = hnt.Status == "protected" ? "Protected" : hnt.Status == "suggested" ? "Suggested" : hnt.Status == "covered" ? "Covered" : "When it's on";
                var chip = Chip(word, col); DockPanel.SetDock(chip, Dock.Left); hd.Children.Add(chip);
                if (hnt.Status == "default") ((TextBlock)((Border)chip).Child).Foreground = Ui.R("Text");
                var lt = OneLine(Ui.T(hnt.Label, 13.5, true)); lt.VerticalAlignment = VerticalAlignment.Center; hd.Children.Add(lt);
                row.Children.Add(hd);
                row.Children.Add(Ui.Muted(hnt.Note, 12.5, 2));
                row.Children.Add(Mono(hnt.Path, Ui.R("Muted")));
                sp.Children.Add(Card(row, 6));
            }
            if (c.Fam == null || c.Fam.Vault == null || !c.Fam.Vault.Installed) sp.Children.Add(Ui.Muted("With Hallow Vault installed, the game-save folders it knows are suggested here too.", 11.5, 6));
            // protected + allowed lists
            if (cfa != null && cfa.Read)
            {
                var lists = new StackPanel();
                lists.Children.Add(Ui.T("Folders you added", 13.5, true, null, 4));
                if (cfa.Protected.Count == 0) lists.Children.Add(Ui.Muted(cfa.ListsHidden ? "Windows only shows this list to administrators here." : "None - only Windows' own list (Documents, Pictures, Videos, Music, Desktop, Favorites).", 12, 8));
                foreach (var p in cfa.Protected) lists.Children.Add(Mono(p, Ui.R("Muted")));
                lists.Children.Add(Ui.T("Apps you allowed", 13.5, true, null, 4));
                if (cfa.Allowed.Count == 0) lists.Children.Add(Ui.Muted(cfa.ListsHidden ? "Windows only shows this list to administrators here." : "None - apps Windows already trusts are allowed automatically.", 12, 0));
                foreach (var p in cfa.Allowed) lists.Children.Add(Mono(p, Ui.R("Muted")));
                sp.Children.Add(Card(lists, 10));
            }
            var b = Ui.Row(Ui.Btn("Protected folders", () => c.RunFix(Ransom.Page), false, "Opens Windows Security > Ransomware protection"), Ui.Btn("Allow an app", () => c.RunFix(Ransom.Page), false, "Opens Windows Security > Ransomware protection, where \"Allow an app through Controlled folder access\" is"));
            b.Margin = new Thickness(0, 0, 0, 10); sp.Children.Add(b);
            sp.Children.Add(Ui.Muted("Hallow Guard only reads these settings. It never turns Controlled folder access on or off and never adds folders or apps - each button opens Windows Security's Ransomware protection page, where you decide.", 11.5, 0));
            return sp;
        }
    }
}
