// Hallow Guard v1.10: the "Recently blocked by Ransomware protection" card - on the Overview (when something was blocked in the last
// two weeks) and at the top of the Ransomware page. Read-only: "Allow in Windows Security" opens Windows Security at Ransomware
// protection > Allow an app through Controlled folder access; Windows asks for admin there and you add the app yourself.
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
        public const int CardRows = 5;

        // overview: only when there's something to say (blocks, or the log can't be read while Controlled folder access is on)
        bool ShowBlockedOnOverview()
        {
            if (c.BlockedApps != null && c.BlockedApps.Count > 0) return true;
            var cfa = c.Facts == null ? null : c.Facts.Cfa;
            return c.Blocks != null && !c.Blocks.Readable && cfa != null && Ransom.IsOn(cfa.Mode);
        }

        FrameworkElement BlockedCard(bool full)
        {
            var sp = new StackPanel();
            var apps = c.BlockedApps ?? new List<BlockedApp>();
            var read = c.Blocks;
            var head = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
            var allow = Ui.Btn("Allow in Windows Security", () => c.RunFix(CfaBlocks.AllowPage), apps.Count > 0 || (read != null && !read.Readable),
                "Opens Windows Security > Ransomware protection > Allow an app through Controlled folder access. Windows asks for admin; Hallow Guard never adds apps itself.");
            allow.VerticalAlignment = VerticalAlignment.Top; DockPanel.SetDock(allow, Dock.Right); head.Children.Add(allow);
            bool problem = read != null && !read.Readable;
            var title = read == null ? "Checking what Ransomware protection blocked..." : problem ? "Recently blocked apps: can't read Defender's log" : CfaBlocks.Headline(apps);
            var color = problem ? Ui.Info : apps.Count == 0 ? Ui.Green : apps.Any(a => a.Trust == "check") ? Ui.Amber : Ui.Info;
            var ht = new StackPanel();
            ht.Children.Add(IconRow(problem ? "circle-info" : apps.Count == 0 ? "circle-check" : "lock", color, title, 14.5));
            if (problem) ht.Children.Add(Ui.Muted(CfaBlocks.ProblemText(read), 12.5, 0));
            else if (read != null && apps.Count == 0) ht.Children.Add(Ui.Muted("Nothing in the last " + CfaBlocks.Days + " days. When Controlled folder access stops an app from changing a protected folder, it's listed here.", 12.5, 0));
            else if (apps.Count > 0) ht.Children.Add(Ui.Muted("In the last " + CfaBlocks.Days + " days, from Microsoft Defender's own log. Nothing was lost - each change was stopped until you allow the app.", 12.5, 0));
            head.Children.Add(ht);
            sp.Children.Add(head);
            int shown = 0;
            foreach (var a in apps)
            {
                if (!full && shown >= CardRows) break;
                shown++;
                sp.Children.Add(Look.IsHud ? Hud.Divider(9, 9) : (UIElement)new Border { Height = 1, Background = Ui.R("Line"), Margin = new Thickness(0, 9, 0, 9) });
                sp.Children.Add(BlockedRow(a));
            }
            if (apps.Count > shown) sp.Children.Add(Ui.Muted("and " + (apps.Count - shown) + " more on the Ransomware page", 12, 0));
            if (apps.Count > 0 || problem)
            {
                var steps = Ui.T("In Windows Security: " + CfaBlocks.Steps + ".", 12, true, null, 0); steps.TextWrapping = TextWrapping.Wrap; steps.Margin = new Thickness(0, 10, 0, 0);
                sp.Children.Add(steps);
                if (apps.Any(a => a.Trust == "check")) sp.Children.Add(Ui.Muted("Only allow apps you know and meant to run. If you don't recognise one, scan it first - an app that tries to change your documents without asking is exactly what this protection is for.", 11.5, 0));
            }
            if (!full && apps.Count > 0)
            {
                var more = Ui.Btn("Ransomware page", () => Show("ransomware")); more.HorizontalAlignment = HorizontalAlignment.Left; more.Margin = new Thickness(0, 8, 0, 0);
                sp.Children.Add(more);
            }
            return Card(sp, 10);
        }

        FrameworkElement BlockedRow(BlockedApp a)
        {
            var row = new DockPanel();
            bool trusted = a.Trust == "trusted";
            if (!trusted && System.IO.File.Exists(a.Exe) && !Snap.On)
            {
                var sb = ScanButton(a.Exe); sb.VerticalAlignment = VerticalAlignment.Center; sb.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(sb, Dock.Right); row.Children.Add(sb);
            }
            else if (!trusted && Snap.On)
            {
                var sb = Ui.Btn("Scan with Defender", () => { }); sb.VerticalAlignment = VerticalAlignment.Center; sb.Margin = new Thickness(12, 0, 0, 0); DockPanel.SetDock(sb, Dock.Right); row.Children.Add(sb);
            }
            var txt = new StackPanel();
            var hd = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 2) };
            var chip = Chip(trusted ? "Trusted publisher" : "Check before allowing", trusted ? Ui.Green : Ui.Amber); hd.Children.Add(chip);
            var nm = OneLine(Ui.T(a.Display, 13.5, true)); nm.VerticalAlignment = VerticalAlignment.Center; hd.Children.Add(nm);
            if (!a.Display.Equals(a.Name, StringComparison.OrdinalIgnoreCase)) { var fn = Ui.Muted("  " + a.Name, 12, 0); fn.VerticalAlignment = VerticalAlignment.Center; hd.Children.Add(fn); }
            if (a.AuditOnly) { var au = Chip("Audit only", Ui.Info); au.Margin = new Thickness(8, 0, 0, 0); hd.Children.Add(au); }
            txt.Children.Add(hd);
            txt.Children.Add(Ui.Muted(a.Why + "   //   " + CfaBlocks.CountLine(a, DateTime.Now), 12.5, 2));
            var folder = a.Folders.Count == 0 ? null : a.Folders[0];
            txt.Children.Add(Ui.Muted("Tried to write to " + CfaBlocks.FolderWord(folder) + (a.Folders.Count > 1 ? " (and " + (a.Folders.Count - 1) + " more)" : ""), 12.5, 2));
            if (folder != null) txt.Children.Add(Mono(folder, Ui.R("Muted")));
            txt.Children.Add(Mono(a.Exe, Ui.R("Muted")));
            row.Children.Add(txt);
            return row;
        }
    }
}
