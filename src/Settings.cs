// Hallow Guard settings: %APPDATA%\HallowGuard\settings.json. The VirusTotal key (optional, your own) is kept encrypted for
// this Windows user (DPAPI) and never written in plain text, never logged and never sent anywhere but VirusTotal.
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace HallowGuard
{
    // one scan Hallow Guard ran (through Defender's engine), newest first in Settings.Scans
    [DataContract]
    public class ScanRecord
    {
        [DataMember] public string Kind;      // quick | full | custom | download
        [DataMember] public string Target;    // the folder or file (custom / download)
        [DataMember] public string Start;     // ISO
        [DataMember] public string End;
        [DataMember] public string Result;    // clean | threats | cancelled | error
        [DataMember] public int Threats;
        [DataMember] public string Note;
        [DataMember] public bool Away;        // v1.3: the quick scan while you were away
    }

    [DataContract]
    public class GuardSettings
    {
        // developer tests: HALLOW_GUARD_TESTDIR = data folder (and a separate pipe); HALLOW_GUARD_FAKE=1 = made-up system checks,
        // threats and leftovers, and HALLOW_GUARD_MPCMDRUN as the scan engine; HALLOW_GUARD_HEADLESS=1 = no windows or tray at all.
        public static readonly string TestDir = Env("HALLOW_GUARD_TESTDIR");
        public static readonly bool Fake = TestDir != null && Env("HALLOW_GUARD_FAKE") == "1";
        public static readonly bool Headless = TestDir != null && Env("HALLOW_GUARD_HEADLESS") == "1";
        public static bool Frozen;   // --snap: never saved
        static string Env(string n) { var v = Environment.GetEnvironmentVariable(n); return string.IsNullOrWhiteSpace(v) ? null : v; }
        public static string Dir { get { return TestDir ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HallowGuard"); } }
        static string FilePath { get { return Path.Combine(Dir, "settings.json"); } }

        [DataMember] public bool UseHallowIcon = true;
        [DataMember] public bool UseHallowAccent = true;
        [DataMember] public bool WatchDownloads;            // off by default
        [DataMember] public bool WeeklyReminder = true;     // a reminder when nothing was scanned for 7 days
        [DataMember] public string VtKey;                   // DPAPI-protected VirusTotal API key (null = none: Look up opens the website)
        [DataMember] public string LastReminder;
        [DataMember] public string LastUpdateCheck;
        [DataMember] public string LastCrashShown;
        [DataMember] public bool TrayHintShown;
        [DataMember] public List<ScanRecord> Scans;
        // v1.3: a quick scan while you're away (off by default; "daily" or "weekly"), the weekly report and its one balloon
        [DataMember] public bool AwayScan;
        [DataMember] public string AwayEvery = "weekly";
        [DataMember] public bool ReportNotify = true;
        [DataMember] public string LastReportWeek;
        [DataMember] public string LastReportNotified;

        [OnDeserializing] void Defaults(StreamingContext c) { UseHallowIcon = true; UseHallowAccent = true; WeeklyReminder = true; AwayEvery = "weekly"; ReportNotify = true; }

        public static GuardSettings Load()
        {
            try
            {
                if (File.Exists(FilePath))
                    using (var f = File.OpenRead(FilePath))
                    {
                        var s = (GuardSettings)new DataContractJsonSerializer(typeof(GuardSettings)).ReadObject(f);
                        if (s != null) { s.Fix(); return s; }
                    }
            }
            catch { }
            var d = new GuardSettings(); d.Fix(); return d;
        }
        void Fix()
        {
            if (Scans == null) Scans = new List<ScanRecord>();
            if (AwayEvery != "daily") AwayEvery = "weekly";
            Scans.RemoveAll(x => x == null);
            if (Scans.Count > 30) Scans.RemoveRange(30, Scans.Count - 30);
        }
        public void AddScan(ScanRecord r) { lock (Scans) { Scans.Insert(0, r); if (Scans.Count > 30) Scans.RemoveRange(30, Scans.Count - 30); } }
        public ScanRecord LastFinishedScan()
        {
            lock (Scans) foreach (var s in Scans) if (s.Result == "clean" || s.Result == "threats") return s;
            return null;
        }

        static readonly object saveLock = new object();
        public void Save()
        {
            if (Frozen) return;
            lock (saveLock)
            {
                try
                {
                    Directory.CreateDirectory(Dir);
                    var tmp = FilePath + ".tmp";
                    lock (Scans) using (var f = File.Create(tmp)) new DataContractJsonSerializer(typeof(GuardSettings)).WriteObject(f, this);
                    for (int i = 0; ; i++) { try { if (File.Exists(FilePath)) File.Replace(tmp, FilePath, null); else File.Move(tmp, FilePath); break; } catch { if (i >= 5) throw; Thread.Sleep(50); } }
                }
                catch { }
            }
        }

        // ---- the VirusTotal key, encrypted for this Windows user
        static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Hallow Guard VirusTotal v1");
        public static string Protect(string key) { return Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(key), Entropy, DataProtectionScope.CurrentUser)); }
        public static string Unprotect(string s)
        {
            try { return string.IsNullOrEmpty(s) ? null : Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(s), Entropy, DataProtectionScope.CurrentUser)); }
            catch { return null; }
        }
        public string GetVtKey() { return Unprotect(VtKey); }
        public void SetVtKey(string key)
        {
            key = (key ?? "").Trim();
            VtKey = key.Length == 0 ? null : Protect(key);
            Crash.Secrets = key.Length == 0 ? new string[0] : new[] { key };
        }
    }
}
