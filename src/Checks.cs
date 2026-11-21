// Hallow Guard - the safety score: read-only checks of what protects this PC (Microsoft Defender, firewall, SmartScreen,
// Windows Update, BitLocker, UAC, Secure Boot, Memory integrity). Nothing here changes a setting: a "Fix" button only opens the
// right Windows Security / Settings page, and the one admin action (checking BitLocker) runs only when you click it, through UAC.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;
using Microsoft.Win32;

namespace HallowGuard
{
    // everything the checks look at; null = couldn't be read
    public class SystemFacts
    {
        public bool DefenderRead;                 // Defender's status could be read at all
        public bool? AvEnabled, RealTime, Tamper;
        public int? SigAgeDays;
        public DateTime? QuickScan, FullScan;
        public string RunningMode;                // "Normal", "Passive Mode", "EDR Block Mode", ...
        public List<string> OtherAv = new List<string>();      // third-party antivirus registered and switched on
        public List<string> OtherAvOff = new List<string>();   // registered but off / out of date
        public List<string> OtherFirewall = new List<string>();
        public bool? FwDomain, FwPrivate, FwPublic;
        public bool? SmartScreen;
        public DateTime? LastUpdate; public bool? RebootPending;
        public string BitLocker;                  // "on", "off", "encrypting", "paused", null = unknown
        public bool BitLockerFromAdminCheck;
        public bool? Uac, UacPrompts, SecureBoot, MemoryIntegrity;
        public DateTime Now = DateTime.Now;
    }

    public interface ISecurityProbe { SystemFacts Read(); }

    public enum CheckState { Good, Warn, Bad, Unknown, Info }
    public class Check
    {
        public string Id, Title, Line, FixLabel, FixAction;   // FixAction: a windowsdefender:/ms-settings: URI, "scan:quick", "page:scan" or "admin:bitlocker"
        public CheckState State; public int Penalty;
    }

    public static class Score
    {
        public static string Ago(DateTime? t, DateTime now)
        {
            if (t == null) return "never";
            var d = now - t.Value;
            if (d.TotalMinutes < 2) return "just now";
            if (d.TotalHours < 1) return (int)d.TotalMinutes + " minutes ago";
            if (d.TotalHours < 24) { int h = (int)d.TotalHours; return h + (h == 1 ? " hour ago" : " hours ago"); }
            int days = (int)d.TotalDays; if (days < 14) return days + (days == 1 ? " day ago" : " days ago");
            if (days < 60) return (days / 7) + " weeks ago";
            return (days / 30) + " months ago";
        }
        static Check C(string id, string title, CheckState st, int pen, string line, string fixLabel = null, string fix = null)
        { return new Check { Id = id, Title = title, State = st, Penalty = pen, Line = line, FixLabel = fixLabel, FixAction = fix }; }

        // the rules: every check, with what it costs the score. lastGuardScan = the newest scan Hallow Guard ran (may be newer than Defender's own record)
        public static List<Check> Evaluate(SystemFacts f, DateTime? lastGuardScan)
        {
            var r = new List<Check>(); var now = f.Now;
            bool other = f.OtherAv.Count > 0;
            const string threatSettings = "windowsdefender://threatsettings";
            // antivirus
            if (other) r.Add(C("av", "Antivirus", CheckState.Info, 0, string.Join(", ", f.OtherAv) + " protects this PC, so Microsoft Defender steps back (passive mode). That's fine - two antivirus programs at once would get in each other's way."));
            else if (!f.DefenderRead || f.AvEnabled == null) r.Add(C("av", "Antivirus", CheckState.Unknown, 0, "Couldn't read Microsoft Defender's status. Windows Security shows it.", "Open settings", "windowsdefender://threat"));
            else if (f.AvEnabled == true) r.Add(C("av", "Antivirus", CheckState.Good, 0, "Microsoft Defender Antivirus is on."));
            else r.Add(C("av", "Antivirus", CheckState.Bad, 30, "Microsoft Defender Antivirus is off and no other antivirus is registered. This PC isn't protected against malware." + (f.OtherAvOff.Count > 0 ? " (" + string.Join(", ", f.OtherAvOff) + " is installed but switched off or out of date.)" : ""), "Open settings", threatSettings));
            if (!other)
            {
                if (f.RealTime == null) r.Add(C("realtime", "Real-time protection", CheckState.Unknown, 0, "Couldn't read whether real-time protection is on.", "Open settings", threatSettings));
                else if (f.RealTime == true) r.Add(C("realtime", "Real-time protection", CheckState.Good, 0, "On - files are checked the moment they're opened or downloaded."));
                else r.Add(C("realtime", "Real-time protection", CheckState.Bad, 25, "Off - new files aren't checked when they arrive. Windows turns it back on by itself after a while, or you can now.", "Open settings", threatSettings));
                if (f.SigAgeDays == null) r.Add(C("signatures", "Virus definitions", CheckState.Unknown, 0, "Couldn't read how old Defender's virus definitions are."));
                else if (f.SigAgeDays.Value > 7) r.Add(C("signatures", "Virus definitions", CheckState.Bad, 10, "Defender's virus definitions are " + f.SigAgeDays + " days old - new threats may not be recognised. Windows Update normally refreshes them every day.", "Open settings", "windowsdefender://threat"));
                else if (f.SigAgeDays.Value > 2) r.Add(C("signatures", "Virus definitions", CheckState.Warn, 4, "Defender's virus definitions are " + f.SigAgeDays + " days old. They usually update daily.", "Open settings", "windowsdefender://threat"));
                else r.Add(C("signatures", "Virus definitions", CheckState.Good, 0, f.SigAgeDays.Value == 0 ? "Up to date (updated today)." : "Up to date (" + f.SigAgeDays + (f.SigAgeDays == 1 ? " day" : " days") + " old)."));
                if (f.Tamper == null) r.Add(C("tamper", "Tamper protection", CheckState.Unknown, 0, "Couldn't read whether tamper protection is on.", "Open settings", threatSettings));
                else if (f.Tamper == true) r.Add(C("tamper", "Tamper protection", CheckState.Good, 0, "On - other programs can't quietly switch Defender off."));
                else r.Add(C("tamper", "Tamper protection", CheckState.Warn, 8, "Off - malware could switch Defender's protection off without you noticing.", "Open settings", threatSettings));
            }
            // last scan (Defender's own record or one Hallow Guard ran, whichever is newer)
            DateTime? quick = Newest(f.QuickScan, lastGuardScan), full = f.FullScan, any = Newest(quick, full);
            if (other) r.Add(C("scan", "Last scan", CheckState.Info, 0, "Scans are done by " + f.OtherAv[0] + ". Hallow Guard can still ask Defender for a one-off scan.", "Scan now", "page:scan"));
            else if (any == null || (now - any.Value).TotalDays > 14) r.Add(C("scan", "Last scan", CheckState.Warn, 5, any == null ? "No scan on record. A quick scan takes a few minutes." : "The last scan was " + Ago(any, now) + ". A quick scan takes a few minutes.", "Scan now", "scan:quick"));
            else r.Add(C("scan", "Last scan", CheckState.Good, 0, "Quick scan " + Ago(quick, now) + ", full scan " + Ago(full, now) + "."));
            // firewall
            var offProfiles = new List<string>();
            if (f.FwDomain == false) offProfiles.Add("domain"); if (f.FwPrivate == false) offProfiles.Add("private"); if (f.FwPublic == false) offProfiles.Add("public");
            if (f.OtherFirewall.Count > 0 && offProfiles.Count > 0) r.Add(C("firewall", "Firewall", CheckState.Info, 0, f.OtherFirewall[0] + " is the firewall here, so Windows Firewall being off is expected."));
            else if (f.FwDomain == null && f.FwPrivate == null && f.FwPublic == null) r.Add(C("firewall", "Firewall", CheckState.Unknown, 0, "Couldn't read the firewall settings.", "Open settings", "windowsdefender://network"));
            else if (offProfiles.Count == 0) r.Add(C("firewall", "Firewall", CheckState.Good, 0, "Windows Firewall is on for every network type."));
            else r.Add(C("firewall", "Firewall", CheckState.Bad, offProfiles.Contains("public") ? 15 : 10, "Windows Firewall is off for " + string.Join(" and ", offProfiles) + " networks" + (offProfiles.Contains("public") ? " - including public Wi-Fi, where it matters most." : "."), "Open settings", "windowsdefender://network"));
            // SmartScreen
            if (f.SmartScreen == null) r.Add(C("smartscreen", "SmartScreen", CheckState.Unknown, 0, "Couldn't read the SmartScreen setting.", "Open settings", "windowsdefender://appbrowser"));
            else if (f.SmartScreen == true) r.Add(C("smartscreen", "SmartScreen", CheckState.Good, 0, "On - Windows warns before you run unrecognised apps and downloads."));
            else r.Add(C("smartscreen", "SmartScreen", CheckState.Warn, 6, "Off - Windows won't warn you about unrecognised or known-bad apps you download.", "Open settings", "windowsdefender://appbrowser"));
            // Windows Update
            {
                int pen = 0; var st = CheckState.Good; var parts = new List<string>();
                if (f.LastUpdate == null) { parts.Add("Couldn't tell when updates were last installed."); st = CheckState.Unknown; }
                else
                {
                    var days = (now - f.LastUpdate.Value).TotalDays;
                    parts.Add("Last update installed " + Ago(f.LastUpdate, now) + ".");
                    if (days > 45) { pen += 10; st = CheckState.Bad; parts.Add("Windows usually updates every month - check for updates."); }
                    else if (days > 30) { pen += 5; st = CheckState.Warn; parts.Add("It's been a while - check for updates."); }
                }
                if (f.RebootPending == true) { pen += 4; if (st == CheckState.Good || st == CheckState.Unknown) st = CheckState.Warn; parts.Add("A restart is waiting to finish installing updates."); }
                r.Add(C("update", "Windows Update", st, pen, string.Join(" ", parts), st == CheckState.Good ? null : "Open settings", st == CheckState.Good ? null : "ms-settings:windowsupdate"));
            }
            // BitLocker (reading it needs admin on most PCs: then it's "unknown" with a button you can click)
            if (f.BitLocker == null) r.Add(C("bitlocker", "Drive encryption (BitLocker)", CheckState.Unknown, 0, "Windows only tells administrators whether the system drive is encrypted. Click to check - Windows asks for admin first.", "Check (admin)", "admin:bitlocker"));
            else if (f.BitLocker == "on") r.Add(C("bitlocker", "Drive encryption (BitLocker)", CheckState.Good, 0, "The system drive is encrypted - if the PC is stolen, its files can't be read."));
            else if (f.BitLocker == "encrypting") r.Add(C("bitlocker", "Drive encryption (BitLocker)", CheckState.Good, 0, "The system drive is being encrypted right now."));
            else if (f.BitLocker == "paused") r.Add(C("bitlocker", "Drive encryption (BitLocker)", CheckState.Warn, 3, "BitLocker is paused (suspended) on the system drive - usually only for an update. It resumes after a restart.", "Open settings", "control:bitlocker"));
            else r.Add(C("bitlocker", "Drive encryption (BitLocker)", CheckState.Warn, 5, "The system drive isn't encrypted. If the PC is lost or stolen, its files can be read. (Windows Home calls this Device encryption, where available.)", "Open settings", "control:bitlocker"));
            // UAC
            if (f.Uac == null) r.Add(C("uac", "User Account Control", CheckState.Unknown, 0, "Couldn't read the User Account Control setting."));
            else if (f.Uac == false) r.Add(C("uac", "User Account Control", CheckState.Bad, 15, "Off - every program gets full control of the PC without asking.", "Open settings", "uac"));
            else if (f.UacPrompts == false) r.Add(C("uac", "User Account Control", CheckState.Warn, 8, "On, but set to never ask - programs can get admin rights silently.", "Open settings", "uac"));
            else r.Add(C("uac", "User Account Control", CheckState.Good, 0, "On - Windows asks before a program gets admin rights."));
            // Secure Boot (a firmware setting: no button)
            if (f.SecureBoot == null) r.Add(C("secureboot", "Secure Boot", CheckState.Unknown, 0, "Not reported - this PC may start in legacy (BIOS) mode."));
            else if (f.SecureBoot == true) r.Add(C("secureboot", "Secure Boot", CheckState.Good, 0, "On - only trusted software can load while the PC starts."));
            else r.Add(C("secureboot", "Secure Boot", CheckState.Warn, 4, "Off. It's switched on in the PC's firmware (UEFI) settings - only change that if you're comfortable doing so."));
            // Memory integrity
            if (f.MemoryIntegrity == null) r.Add(C("hvci", "Memory integrity", CheckState.Unknown, 0, "Couldn't read the Core isolation setting.", "Open settings", "windowsdefender://coreisolation"));
            else if (f.MemoryIntegrity == true) r.Add(C("hvci", "Memory integrity", CheckState.Good, 0, "On - Core isolation stops malicious drivers from getting into the heart of Windows."));
            else r.Add(C("hvci", "Memory integrity", CheckState.Warn, 4, "Off. Core isolation blocks malicious drivers. (Some older drivers and anti-cheats don't work with it - Windows tells you which.)", "Open settings", "windowsdefender://coreisolation"));
            return r;
        }
        static DateTime? Newest(DateTime? a, DateTime? b) { if (a == null) return b; if (b == null) return a; return a > b ? a : b; }
        public static int Total(List<Check> checks) { return Math.Max(0, Math.Min(100, 100 - checks.Sum(c => c.Penalty))); }
        public static string Label(int score) { return score >= 90 ? "Looking good" : score >= 70 ? "A few things to look at" : "Needs attention"; }
    }

    // the real PC: WMI (Defender, Security Center, updates) and the registry, read-only. Run it on an STA thread (Shell for BitLocker).
    public class WindowsProbe : ISecurityProbe
    {
        public static string BitLockerFile { get { return Path.Combine(GuardSettings.Dir, "bitlocker.txt"); } }

        public SystemFacts Read()
        {
            var f = new SystemFacts();
            Try(() => Defender(f)); Try(() => SecurityCenter(f)); Try(() => Firewall(f)); Try(() => SmartScreen(f));
            Try(() => Updates(f)); Try(() => BitLocker(f)); Try(() => Misc(f));
            return f;
        }
        static void Try(Action a) { try { a(); } catch { } }
        static IEnumerable<ManagementObject> Query(string scope, string wql)
        {
            using (var s = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql), new EnumerationOptions { Timeout = TimeSpan.FromSeconds(20) }))
                foreach (ManagementObject o in s.Get()) yield return o;
        }
        static bool? Bool(ManagementBaseObject o, string p) { try { var v = o[p]; return v == null ? (bool?)null : Convert.ToBoolean(v); } catch { return null; } }
        public static DateTime? CimTime(object v)
        {
            try { if (v == null) return null; var t = ManagementDateTimeConverter.ToDateTime(v.ToString()); return t.Year < 2000 ? (DateTime?)null : t; }
            catch { return null; }
        }

        static void Defender(SystemFacts f)
        {
            foreach (var o in Query(@"root\Microsoft\Windows\Defender", "SELECT * FROM MSFT_MpComputerStatus"))
            {
                f.DefenderRead = true;
                f.AvEnabled = Bool(o, "AntivirusEnabled"); f.RealTime = Bool(o, "RealTimeProtectionEnabled"); f.Tamper = Bool(o, "IsTamperProtected");
                try { var a = o["AntivirusSignatureAge"]; if (a != null) { var n = Convert.ToInt64(a); if (n >= 0 && n < 100000) f.SigAgeDays = (int)n; } } catch { }
                f.QuickScan = CimTime(o["QuickScanEndTime"]); f.FullScan = CimTime(o["FullScanEndTime"]);
                try { f.RunningMode = o["AMRunningMode"] as string; } catch { }
            }
        }
        // productState: bits 12-15 = 1 when the product is switched on
        public static bool ProductOn(uint state) { return ((state >> 12) & 0xF) == 1; }
        public static bool IsMicrosoftDefender(string name) { return name != null && (name.IndexOf("Windows Defender", StringComparison.OrdinalIgnoreCase) >= 0 || name.IndexOf("Microsoft Defender", StringComparison.OrdinalIgnoreCase) >= 0); }
        static void SecurityCenter(SystemFacts f)
        {
            foreach (var o in Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
            {
                var name = o["displayName"] as string; if (string.IsNullOrEmpty(name) || IsMicrosoftDefender(name)) continue;
                uint st = 0; try { st = Convert.ToUInt32(o["productState"]); } catch { }
                if (ProductOn(st)) { if (!f.OtherAv.Contains(name)) f.OtherAv.Add(name); } else if (!f.OtherAvOff.Contains(name)) f.OtherAvOff.Add(name);
            }
            try
            {
                foreach (var o in Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM FirewallProduct"))
                {
                    var name = o["displayName"] as string; if (string.IsNullOrEmpty(name) || name.IndexOf("Windows", StringComparison.OrdinalIgnoreCase) >= 0) continue;
                    uint st = 0; try { st = Convert.ToUInt32(o["productState"]); } catch { }
                    if (ProductOn(st) && !f.OtherFirewall.Contains(name)) f.OtherFirewall.Add(name);
                }
            }
            catch { }
        }
        static RegistryKey Hklm(string path) { return RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64).OpenSubKey(path); }
        static int? Dword(string path, string name)
        {
            try { using (var k = Hklm(path)) { var v = k == null ? null : k.GetValue(name); return v == null ? (int?)null : Convert.ToInt32(v); } }
            catch { return null; }
        }
        static void Firewall(SystemFacts f)
        {
            const string b = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
            const string pol = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\";
            Func<string, string, bool?> one = (reg, polName) => { var p = Dword(pol + polName, "EnableFirewall"); if (p != null) return p != 0; var v = Dword(b + reg, "EnableFirewall"); return v == null ? (bool?)null : v != 0; };
            f.FwDomain = one("DomainProfile", "DomainProfile"); f.FwPrivate = one("StandardProfile", "PrivateProfile"); f.FwPublic = one("PublicProfile", "PublicProfile");
        }
        static void SmartScreen(SystemFacts f)
        {
            var pol = Dword(@"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen");
            if (pol != null) { f.SmartScreen = pol != 0; return; }
            using (var k = Hklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"))
            {
                var v = k == null ? null : k.GetValue("SmartScreenEnabled") as string;
                f.SmartScreen = v == null ? true : !string.Equals(v, "Off", StringComparison.OrdinalIgnoreCase);   // not set = Windows' default (on)
            }
        }
        static void Updates(SystemFacts f)
        {
            using (var k = Hklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")) f.RebootPending = k != null;
            if (f.RebootPending != true) using (var k = Hklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")) f.RebootPending = k != null;
            DateTime? best = null;
            foreach (var o in Query(@"root\cimv2", "SELECT InstalledOn FROM Win32_QuickFixEngineering"))
            {
                var s = o["InstalledOn"] as string; DateTime t;
                if (string.IsNullOrEmpty(s)) continue;
                if (DateTime.TryParse(s, CultureInfo.GetCultureInfo("en-US"), DateTimeStyles.None, out t) || DateTime.TryParse(s, out t))
                    if (t <= DateTime.Now.AddDays(1) && (best == null || t > best)) best = t;
            }
            f.LastUpdate = best;
        }
        // BitLocker protection of the Windows drive: WMI (admins only), then the Shell's own property, then the result of the
        // admin check you can click (bitlocker.txt, written by that check, trusted for 30 days)
        static void BitLocker(SystemFacts f)
        {
            var drive = Path.GetPathRoot(Environment.GetFolderPath(Environment.SpecialFolder.Windows)).TrimEnd('\\');
            try
            {
                foreach (var o in Query(@"root\CIMV2\Security\MicrosoftVolumeEncryption", "SELECT ProtectionStatus, DriveLetter FROM Win32_EncryptableVolume WHERE DriveLetter='" + drive + "'"))
                { var p = Convert.ToInt32(o["ProtectionStatus"]); if (p == 1) { f.BitLocker = "on"; return; } if (p == 0) { f.BitLocker = "off"; return; } }
            }
            catch { }
            try
            {
                var t = Type.GetTypeFromProgID("Shell.Application"); var sh = Activator.CreateInstance(t);
                try
                {
                    var ns = t.InvokeMember("NameSpace", BindingFlags.InvokeMethod, null, sh, new object[] { drive + "\\" });
                    var self = ns.GetType().InvokeMember("Self", BindingFlags.GetProperty, null, ns, null);
                    var v = self.GetType().InvokeMember("ExtendedProperty", BindingFlags.InvokeMethod, null, self, new object[] { "System.Volume.BitLockerProtection" });
                    var s = ShellBitLocker(v == null ? (int?)null : Convert.ToInt32(v));
                    if (s != null) { f.BitLocker = s; return; }
                }
                finally { System.Runtime.InteropServices.Marshal.FinalReleaseComObject(sh); }
            }
            catch { }
            try
            {
                if (File.Exists(BitLockerFile) && (DateTime.Now - File.GetLastWriteTime(BitLockerFile)).TotalDays < 30)
                {
                    var s = File.ReadAllText(BitLockerFile).Trim().ToLowerInvariant();
                    if (s == "on" || s == "off") { f.BitLocker = s; f.BitLockerFromAdminCheck = true; }
                }
            }
            catch { }
        }
        // the Shell's System.Volume.BitLockerProtection: 1 = on, 2 = off, 3 = encrypting, 4 = decrypting, 5 = suspended, 6 = on (locked)
        public static string ShellBitLocker(int? v)
        {
            switch (v ?? 0) { case 1: case 6: return "on"; case 2: case 4: return "off"; case 3: return "encrypting"; case 5: return "paused"; }
            return null;
        }
        static void Misc(SystemFacts f)
        {
            var lua = Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
            f.Uac = lua == null ? true : lua != 0;   // missing = Windows' default (on)
            var cp = Dword(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
            f.UacPrompts = cp == null ? true : cp != 0;
            var sb = Dword(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
            f.SecureBoot = sb == null ? (bool?)null : sb != 0;
            var hv = Dword(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled");
            f.MemoryIntegrity = hv == null ? false : hv != 0;
        }
    }

    // made-up facts for --snap pictures and developer tests (never the real PC)
    public class FakeProbe : ISecurityProbe
    {
        public SystemFacts Facts;
        public FakeProbe(SystemFacts f = null) { Facts = f ?? Sample(); }
        public SystemFacts Read() { return Facts; }
        public static SystemFacts Sample()
        {
            var now = DateTime.Now;
            return new SystemFacts
            {
                DefenderRead = true, AvEnabled = true, RealTime = true, Tamper = true, SigAgeDays = 0, RunningMode = "Normal",
                QuickScan = now.AddDays(-2).AddHours(-3), FullScan = now.AddDays(-23),
                FwDomain = true, FwPrivate = true, FwPublic = true, SmartScreen = true,
                LastUpdate = now.AddDays(-9), RebootPending = true, BitLocker = null,
                Uac = true, UacPrompts = true, SecureBoot = true, MemoryIntegrity = false, Now = now
            };
        }
    }
}
