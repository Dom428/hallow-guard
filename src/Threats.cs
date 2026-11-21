// Hallow Guard - threat history: what Microsoft Defender found (MSFT_MpThreatDetection + MSFT_MpThreat), explained in plain
// words. Read-only: restoring or removing something is done in Windows Security ("Open in Windows Security").
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

namespace HallowGuard
{
    public class ThreatRecord
    {
        public long Id; public string Name; public int Severity; public int Category;
        public List<string> Paths = new List<string>();
        public DateTime? When; public int StatusId; public int ActionId; public bool ActionOk = true;
        public string SeverityText { get { return Threats.SeverityText(Severity); } }
        public string Kind { get { return Threats.KindOf(Name, Category); } }
        public string What { get { return Threats.Explain(Name, Category); } }
        public string Action { get { return Threats.ActionText(StatusId, ActionId, ActionOk); } }
    }

    public interface IThreatSource { List<ThreatRecord> Read(out string error); }

    public static class Threats
    {
        public static string SeverityText(int s) { switch (s) { case 1: return "Low"; case 2: return "Medium"; case 4: return "High"; case 5: return "Severe"; } return "Unknown"; }

        // "Trojan:Win32/Wacatac.B!ml" -> the kind before the colon, in plain words
        public static string KindOf(string name, int category)
        {
            var t = (name ?? "").Split(':')[0].Trim();
            if (t.StartsWith("PUA", StringComparison.OrdinalIgnoreCase) || category == 27) return "Unwanted app";
            if (t.StartsWith("Trojan", StringComparison.OrdinalIgnoreCase)) return "Trojan";
            if (t.StartsWith("HackTool", StringComparison.OrdinalIgnoreCase) || category == 34) return "Hacking tool";
            if (t.StartsWith("Ransom", StringComparison.OrdinalIgnoreCase) || category == 50) return "Ransomware";
            if (t.StartsWith("Backdoor", StringComparison.OrdinalIgnoreCase) || category == 6) return "Backdoor";
            if (t.StartsWith("Worm", StringComparison.OrdinalIgnoreCase) || category == 5) return "Worm";
            if (t.StartsWith("Virus", StringComparison.OrdinalIgnoreCase) || category == 42) return "Virus";
            if (t.StartsWith("Exploit", StringComparison.OrdinalIgnoreCase) || category == 30) return "Exploit";
            if (t.StartsWith("Adware", StringComparison.OrdinalIgnoreCase) || category == 1) return "Adware";
            if (t.StartsWith("Spyware", StringComparison.OrdinalIgnoreCase) || category == 2) return "Spyware";
            if (t.StartsWith("PWS", StringComparison.OrdinalIgnoreCase) || category == 3) return "Password stealer";
            if (t.StartsWith("Behavior", StringComparison.OrdinalIgnoreCase) || category == 46) return "Suspicious behaviour";
            if (t.StartsWith("BrowserModifier", StringComparison.OrdinalIgnoreCase) || category == 13) return "Browser hijacker";
            if (t.StartsWith("SoftwareBundler", StringComparison.OrdinalIgnoreCase) || category == 21) return "Bundler";
            return t.Length > 0 && t.Length < 30 && !t.Contains("/") ? t : "Threat";
        }
        public static string Explain(string name, int category)
        {
            switch (KindOf(name, category))
            {
                case "Unwanted app": return "A potentially unwanted app: not a virus, but it often comes bundled with installers and adds ads, toolbars or junk.";
                case "Trojan": return "A program that pretends to be something harmless so it can get onto the PC and do something else in the background.";
                case "Hacking tool": return "A tool that can be used to break into or tamper with software. Game cheats and licence cracks are often flagged as this.";
                case "Ransomware": return "Malware that locks or encrypts files and asks for money to get them back.";
                case "Backdoor": return "Malware that lets someone else control the PC remotely.";
                case "Worm": return "Malware that copies itself to other PCs or drives.";
                case "Virus": return "Malware that attaches itself to other files.";
                case "Exploit": return "Code that abuses a bug in a program to get in. Keeping Windows and apps updated closes these holes.";
                case "Adware": return "Software that shows unwanted ads.";
                case "Spyware": return "Software that watches what you do and sends it somewhere.";
                case "Password stealer": return "Malware that tries to steal saved passwords and logins. Change important passwords from a clean device.";
                case "Suspicious behaviour": return "Defender saw a program act like malware (rather than recognising the file itself).";
                case "Browser hijacker": return "Software that changes your browser's home page, search engine or settings without asking.";
                case "Bundler": return "An installer that sneaks extra programs onto the PC.";
            }
            return "Something Defender recognises as harmful.";
        }
        // ThreatStatusID / CleaningActionID -> what happened, in plain words
        public static string ActionText(int status, int action, bool ok)
        {
            switch (status)
            {
                case 2: return "Cleaned - the harmful part was removed.";
                case 3: return "Quarantined - locked away where it can't run. You can remove or restore it in Windows Security.";
                case 4: return "Removed from the PC.";
                case 5: return "Allowed - someone chose to let it run on this PC.";
                case 6: return "Blocked from running.";
                case 102: return "Defender couldn't quarantine it - open Windows Security to deal with it.";
                case 103: return "Defender couldn't remove it - open Windows Security to deal with it.";
                case 104: return "Allowing it failed.";
                case 105: return "Abandoned - the file was gone before Defender could act.";
                case 107: return "Defender couldn't block it - open Windows Security to deal with it.";
                case 1:
                    switch (action)
                    {
                        case 2: return ok ? "Quarantined - locked away where it can't run." : "Defender tried to quarantine it but couldn't - open Windows Security.";
                        case 3: return ok ? "Removed from the PC." : "Defender tried to remove it but couldn't - open Windows Security.";
                        case 6: return "Allowed - someone chose to let it run on this PC.";
                        case 10: return "Blocked from running.";
                    }
                    return "Found - waiting for you to choose what to do in Windows Security.";
            }
            return ok ? "Handled by Defender." : "Defender couldn't finish handling it - open Windows Security.";
        }
        // "file:_C:\x\y.exe" / "containerfile:_..." / "process:_pid:12,ProcessStart:..." -> the path part
        public static string CleanResource(string r)
        {
            if (string.IsNullOrEmpty(r)) return r;
            int i = r.IndexOf(":_"); var s = i > 0 && i < 20 ? r.Substring(i + 2) : r;
            int arrow = s.IndexOf("->"); if (arrow > 0) s = s.Substring(0, arrow);
            return s.Trim();
        }
    }

    // the real history from Defender (WMI, read-only). Windows may only show it to administrators: then error says so.
    public class WindowsThreatSource : IThreatSource
    {
        public List<ThreatRecord> Read(out string error)
        {
            error = null; var list = new List<ThreatRecord>();
            try
            {
                var names = new Dictionary<long, Tuple<string, int, int>>();
                const string scope = @"root\Microsoft\Windows\Defender";
                using (var s = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery("SELECT ThreatID, ThreatName, SeverityID, CategoryID FROM MSFT_MpThreat")))
                    foreach (ManagementObject o in s.Get())
                        try { names[Convert.ToInt64(o["ThreatID"])] = Tuple.Create(o["ThreatName"] as string, ToInt(o["SeverityID"]), ToInt(o["CategoryID"])); } catch { }
                using (var s = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery("SELECT * FROM MSFT_MpThreatDetection")))
                    foreach (ManagementObject o in s.Get())
                    {
                        var t = new ThreatRecord();
                        try { t.Id = Convert.ToInt64(o["ThreatID"]); } catch { }
                        Tuple<string, int, int> n; if (names.TryGetValue(t.Id, out n)) { t.Name = n.Item1; t.Severity = n.Item2; t.Category = n.Item3; }
                        if (t.Name == null) t.Name = "Threat " + t.Id;
                        t.When = WindowsProbe.CimTime(o["InitialDetectionTime"]) ?? WindowsProbe.CimTime(o["LastThreatStatusChangeTime"]);
                        t.StatusId = ToInt(o["ThreatStatusID"]); t.ActionId = ToInt(o["CleaningActionID"]);
                        try { var a = o["ActionSuccess"]; if (a != null) t.ActionOk = Convert.ToBoolean(a); } catch { }
                        try { var res = o["Resources"] as string[]; if (res != null) foreach (var r in res) { var c = Threats.CleanResource(r); if (!string.IsNullOrEmpty(c) && !t.Paths.Contains(c)) t.Paths.Add(c); } } catch { }
                        list.Add(t);
                    }
            }
            catch (UnauthorizedAccessException) { error = "Windows only shows the threat history to administrators here. Windows Security's Protection history shows it."; }
            catch (ManagementException e) { error = e.ErrorCode == ManagementStatus.AccessDenied ? "Windows only shows the threat history to administrators here. Windows Security's Protection history shows it." : "Couldn't read Defender's threat history (" + e.ErrorCode + ")."; }
            catch (Exception e) { error = "Couldn't read Defender's threat history: " + e.Message; }
            return list.OrderByDescending(x => x.When ?? DateTime.MinValue).ToList();
        }
        static int ToInt(object v) { try { return v == null ? 0 : Convert.ToInt32(v); } catch { return 0; } }
    }

    public class FakeThreatSource : IThreatSource
    {
        public List<ThreatRecord> Items;
        public FakeThreatSource(List<ThreatRecord> items = null) { Items = items ?? Sample(); }
        public List<ThreatRecord> Read(out string error) { error = null; return Items; }
        public static List<ThreatRecord> Sample()
        {
            var now = DateTime.Now;
            return new List<ThreatRecord> {
                new ThreatRecord { Id = 1, Name = "PUA:Win32/Presenoker", Severity = 1, Category = 27, StatusId = 3, ActionId = 2, When = now.AddDays(-4).AddHours(-2), Paths = { @"C:\Users\Alex\Downloads\free-video-converter-setup.exe" } },
                new ThreatRecord { Id = 2, Name = "Trojan:Win32/Wacatac.B!ml", Severity = 5, Category = 8, StatusId = 4, ActionId = 3, When = now.AddDays(-37), Paths = { @"C:\Users\Alex\AppData\Local\Temp\patch_v2.exe" } },
                new ThreatRecord { Id = 3, Name = "HackTool:Win32/Keygen", Severity = 2, Category = 34, StatusId = 5, ActionId = 6, When = now.AddDays(-80), Paths = { @"D:\Old games\keygen.exe" } } };
        }
    }
}
