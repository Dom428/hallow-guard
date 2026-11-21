// Hallow Guard v1.2 - ransomware protection: Windows' Controlled folder access (CFA), read-only. Guard reads whether it's on,
// which folders are protected and which apps are allowed (WMI MSFT_MpPreference), explains it, suggests folders worth protecting
// (Documents, Pictures, Desktop and game saves - Saved Games and the save folders Hallow Vault knows, if its status.json lists any)
// and warns that CFA can stop games from writing saves. Every button only opens windowsdefender://ransomwareprotection/ -
// Guard never turns CFA on or off, and never adds folders or apps.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;

namespace HallowGuard
{
    public class CfaFacts
    {
        public bool Read;                 // MSFT_MpPreference could be read at all
        public int? Mode;                 // EnableControlledFolderAccess: 0 off, 1 on, 2 audit, 3 block disk changes only, 4 audit disk changes only
        public List<string> Protected = new List<string>();   // folders added on top of Windows' own list
        public List<string> Allowed = new List<string>();     // apps allowed through
        public bool ListsHidden;          // Windows only shows the lists to administrators on this PC
    }

    public class FolderHint
    {
        public string Label, Path, Status, Note;   // Status: protected | default | covered | suggested
    }

    // the user's folders that matter here (tests and --snap pass made-up ones)
    public class KnownFolders
    {
        public string Documents, Pictures, Desktop, SavedGames;
        public static KnownFolders Current()
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return new KnownFolders
            {
                Documents = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), Pictures = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                Desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), SavedGames = Path.Combine(profile, "Saved Games")
            };
        }
    }

    public static class Ransom
    {
        public const string Page = "windowsdefender://ransomwareprotection/";
        public const int OffPoints = 3, AuditPoints = 2;

        public static bool IsOn(int? mode) { return mode == 1 || mode == 3; }
        public static string ModeWord(int? mode)
        {
            switch (mode ?? -1) { case 0: return "off"; case 1: return "on"; case 2: return "audit"; case 3: return "disk-only"; case 4: return "disk-audit"; }
            return null;
        }
        public static string ModeText(int? mode)
        {
            switch (mode ?? -1)
            {
                case 0: return "Off";
                case 1: return "On";
                case 2: return "Audit mode (only logs, blocks nothing)";
                case 3: return "Blocks disk changes only (folders aren't protected)";
                case 4: return "Audits disk changes only";
            }
            return "Unknown";
        }

        // the "Ransomware protection" check in the Windows group: counts lightly (off 3, audit 2)
        public static Check Evaluate(CfaFacts c, List<string> otherAv)
        {
            const string title = "Ransomware protection";
            var ch = new Check { Id = "cfa", Title = title, FixLabel = "Show me", FixAction = "page:ransomware" };
            if (otherAv != null && otherAv.Count > 0) { ch.State = CheckState.Info; ch.Line = "Controlled folder access is part of Microsoft Defender. " + otherAv[0] + " protects this PC instead - check its own ransomware shield."; ch.FixLabel = null; ch.FixAction = null; return ch; }
            if (c == null || !c.Read || c.Mode == null) { ch.State = CheckState.Unknown; ch.Line = "Couldn't read whether Controlled folder access is on. Windows Security shows it."; return ch; }
            if (c.Mode == 1) { ch.State = CheckState.Good; ch.Line = "Controlled folder access is on - apps Windows doesn't trust can't change files in your protected folders." + (c.Protected.Count > 0 ? " " + c.Protected.Count + " extra " + (c.Protected.Count == 1 ? "folder" : "folders") + " protected." : ""); return ch; }
            if (c.Mode == 2 || c.Mode == 4) { ch.State = CheckState.Warn; ch.Penalty = AuditPoints; ch.Line = "Controlled folder access is in audit mode: it only notes what it would have blocked. Switch it on to stop ransomware from changing your files."; return ch; }
            if (c.Mode == 3) { ch.State = CheckState.Warn; ch.Penalty = AuditPoints; ch.Line = "Controlled folder access only blocks changes to the disk itself - your folders aren't protected from ransomware."; return ch; }
            ch.State = CheckState.Warn; ch.Penalty = OffPoints;
            ch.Line = "Controlled folder access is off. It stops ransomware from locking your documents and pictures. It can block some games from saving - you can allow them.";
            return ch;
        }

        static bool Under(string path, string root)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(root)) return false;
            var p = path.TrimEnd('\\'); var r = root.TrimEnd('\\');
            return p.Equals(r, StringComparison.OrdinalIgnoreCase) || p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
        }

        // save folders Hallow Vault lists in its status.json (top-level "saveFolders", or per game "saveDirs" / "saveFolders" /
        // "savePaths" / "saves" - a string or a list). Vault versions that don't list them give nothing; switched-off games are skipped.
        public static List<string> VaultSaveFolders(Dictionary<string, object> status)
        {
            var r = new List<string>();
            if (status == null) return r;
            Action<object> add = v =>
            {
                if (v is string) { var s = ((string)v).Trim(); if (s.Length > 2 && s.Contains(":\\") && !r.Contains(s, StringComparer.OrdinalIgnoreCase)) r.Add(s.TrimEnd('\\')); }
                else if (v is System.Collections.IEnumerable) foreach (var x in (System.Collections.IEnumerable)v) if (x is string) { var s = ((string)x).Trim(); if (s.Length > 2 && s.Contains(":\\") && !r.Contains(s.TrimEnd('\\'), StringComparer.OrdinalIgnoreCase)) r.Add(s.TrimEnd('\\')); }
            };
            add(J.Get(status, "saveFolders"));
            foreach (var g in J.List(status, "games"))
            {
                if (J.Bool(g, "off") == true) continue;
                foreach (var k in new[] { "saveDirs", "saveFolders", "savePaths", "saves" }) { var v = J.Get(g, k); if (v is string || (v is System.Collections.IEnumerable && !(v is Dictionary<string, object>))) add(v); }
            }
            return r;
        }

        // the folders worth protecting, and where each stands. exists: whether a folder is there (tests and --snap pass their own)
        public static List<FolderHint> Suggest(CfaFacts c, KnownFolders k, IEnumerable<string> vaultFolders, Func<string, bool> exists)
        {
            var r = new List<FolderHint>();
            bool on = c != null && IsOn(c.Mode) && c.Mode == 1;
            var prot = c == null ? new List<string>() : c.Protected;
            var defaults = new[] { Tuple.Create("Documents", k.Documents), Tuple.Create("Pictures", k.Pictures), Tuple.Create("Desktop", k.Desktop) };
            foreach (var d in defaults)
            {
                if (string.IsNullOrEmpty(d.Item2)) continue;
                r.Add(new FolderHint { Label = d.Item1, Path = d.Item2, Status = on ? "protected" : "default", Note = on ? "Protected (Windows includes it)." : "Windows protects it as soon as Controlled folder access is on." });
            }
            Func<string, Tuple<string, string>> coveredBy = p =>
            {
                foreach (var d in defaults) if (Under(p, d.Item2)) return Tuple.Create(d.Item1, d.Item2);
                foreach (var x in prot) if (Under(p, x)) return Tuple.Create(Path.GetFileName(x.TrimEnd('\\')), x);
                return null;
            };
            var games = new List<Tuple<string, string>>();
            if (!string.IsNullOrEmpty(k.SavedGames) && exists(k.SavedGames)) games.Add(Tuple.Create("Saved Games", k.SavedGames));
            if (!string.IsNullOrEmpty(k.Documents) && exists(Path.Combine(k.Documents, "My Games"))) games.Add(Tuple.Create("My Games", Path.Combine(k.Documents, "My Games")));
            foreach (var v in vaultFolders ?? new string[0]) if (exists(v) && !games.Any(g => g.Item2.Equals(v, StringComparison.OrdinalIgnoreCase))) games.Add(Tuple.Create("Game saves (from Hallow Vault)", v));
            foreach (var g in games)
            {
                var cov = coveredBy(g.Item2);
                var h = new FolderHint { Label = g.Item1, Path = g.Item2 };
                bool inList = prot.Any(x => x.TrimEnd('\\').Equals(g.Item2.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));
                if (inList) { h.Status = on ? "protected" : "default"; h.Note = on ? "Protected (you added it)." : "On your list - protected once Controlled folder access is on."; }
                else if (cov != null) { h.Status = "covered"; h.Note = "Inside " + cov.Item1 + ", so it's protected along with it" + (on ? "" : " once it's on") + ". Games that save here may need to be allowed."; }
                else { h.Status = "suggested"; h.Note = "Worth adding under Protected folders. Then allow the games that save here, or they can't write their saves."; }
                r.Add(h);
            }
            return r;
        }

        // MSFT_MpPreference values -> CfaFacts. Non-admins may get "N/A: Must be an administrator..." instead of a list.
        public static CfaFacts FromPreference(object enable, object protectedFolders, object allowedApps)
        {
            var c = new CfaFacts { Read = true };
            try { if (enable != null) c.Mode = Convert.ToInt32(enable); } catch { }
            Action<object, List<string>> list = (v, into) =>
            {
                if (v is string) v = new[] { (string)v };
                var arr = v as System.Collections.IEnumerable; if (arr == null) return;
                foreach (var x in arr)
                {
                    var s = x as string; if (string.IsNullOrWhiteSpace(s)) continue;
                    if (s.StartsWith("N/A", StringComparison.OrdinalIgnoreCase)) { c.ListsHidden = true; continue; }
                    if (!into.Contains(s, StringComparer.OrdinalIgnoreCase)) into.Add(s.Trim());
                }
            };
            list(protectedFolders, c.Protected); list(allowedApps, c.Allowed);
            return c;
        }
    }

    public interface ICfaSource { CfaFacts Read(); }

    // the real PC: Defender's preferences over WMI, read-only
    public class WindowsCfa : ICfaSource
    {
        public CfaFacts Read()
        {
            try
            {
                using (var s = new ManagementObjectSearcher(new ManagementScope(@"root\Microsoft\Windows\Defender"), new ObjectQuery("SELECT EnableControlledFolderAccess, ControlledFolderAccessProtectedFolders, ControlledFolderAccessAllowedApplications FROM MSFT_MpPreference"), new EnumerationOptions { Timeout = TimeSpan.FromSeconds(20) }))
                    foreach (ManagementObject o in s.Get())
                    {
                        object e = null, p = null, a = null;
                        try { e = o["EnableControlledFolderAccess"]; } catch { }
                        try { p = o["ControlledFolderAccessProtectedFolders"]; } catch { }
                        try { a = o["ControlledFolderAccessAllowedApplications"]; } catch { }
                        return Ransom.FromPreference(e, p, a);
                    }
            }
            catch { }
            return new CfaFacts();
        }
    }
}
