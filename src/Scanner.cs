// Hallow Guard - scans through Microsoft Defender's own engine (MpCmdRun.exe -Scan): quick, full, a folder or one file.
// Hallow Guard has no engine of its own and never changes Defender's settings. Also "Watch Downloads": a new file in
// Downloads is scanned once it has finished downloading (size steady, not a .crdownload / .part / .tmp file).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace HallowGuard
{
    public static class MpCmd
    {
        // the newest Defender platform's MpCmdRun.exe (%ProgramData%\Microsoft\Windows Defender\Platform\<version>\), else the
        // one in %ProgramFiles%\Windows Defender. Developer tests: HALLOW_GUARD_MPCMDRUN (a stand-in), only with a test folder.
        public static string Find()
        {
            if (GuardSettings.TestDir != null)
            {
                var t = Environment.GetEnvironmentVariable("HALLOW_GUARD_MPCMDRUN");
                return string.IsNullOrEmpty(t) ? null : t;
            }
            return FindIn(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        }
        public static string FindIn(string programData, string programFiles)
        {
            try
            {
                var plat = Path.Combine(programData, @"Microsoft\Windows Defender\Platform");
                if (Directory.Exists(plat))
                {
                    var best = Directory.GetDirectories(plat)
                        .Select(d => { Version v; return new { d, v = Version.TryParse(Path.GetFileName(d).Split('-')[0], out v) ? v : null }; })
                        .Where(x => x.v != null && File.Exists(Path.Combine(x.d, "MpCmdRun.exe")))
                        .OrderByDescending(x => x.v).FirstOrDefault();
                    if (best != null) return Path.Combine(best.d, "MpCmdRun.exe");
                }
            }
            catch { }
            var pf = Path.Combine(programFiles, @"Windows Defender\MpCmdRun.exe");
            return File.Exists(pf) ? pf : null;
        }

        // MpCmdRun arguments: quick = ScanType 1, full = 2, a folder or file = 3 with -File
        public static string Args(string kind, string target)
        {
            if (kind == "quick") return "-Scan -ScanType 1";
            if (kind == "full") return "-Scan -ScanType 2";
            if (string.IsNullOrEmpty(target)) throw new ArgumentException("no file or folder to scan");
            if (target.IndexOf('"') >= 0) throw new ArgumentException("bad path");
            var t = target.EndsWith("\\") ? target + "\\" : target;   // "C:\" would escape the closing quote
            return "-Scan -ScanType 3 -File \"" + t + "\"";
        }

        // MpCmdRun's exit code (0 = nothing found, 2 = threats found) and its output -> clean / threats / error
        public static string Parse(int exit, IList<string> lines, out int threats, out List<string> names)
        {
            names = new List<string>(); threats = 0;
            foreach (var l in lines)
            {
                var m = Regex.Match(l ?? "", @"^\s*Threat\s*:\s*(.+?)\s*$");
                if (m.Success && !names.Contains(m.Groups[1].Value)) names.Add(m.Groups[1].Value);
                var c = Regex.Match(l ?? "", @"found (\d+) threats?", RegexOptions.IgnoreCase);
                if (c.Success) threats = Math.Max(threats, int.Parse(c.Groups[1].Value));
            }
            threats = Math.Max(threats, names.Count);
            if (exit == 2 || threats > 0) { if (threats == 0) threats = 1; return "threats"; }
            if (exit == 0) return "clean";
            return "error";
        }
    }

    // one running scan
    public class ScanJob
    {
        public readonly string Kind, Target; public DateTime Start = DateTime.Now;
        public volatile bool Done; public string Result, Error; public int Threats; public List<string> Names = new List<string>();
        public readonly List<string> Lines = new List<string>();
        public event Action<ScanJob> Finished;
        Process p; volatile bool cancelled; readonly string exe;

        public ScanJob(string exe, string kind, string target) { this.exe = exe; Kind = kind; Target = target; }
        public TimeSpan Elapsed { get { return DateTime.Now - Start; } }

        public void Run()
        {
            new Thread(() =>
            {
                int exit = -1;
                try
                {
                    if (exe == null || !File.Exists(exe)) throw new Exception("Microsoft Defender's scanner (MpCmdRun.exe) wasn't found on this PC.");
                    var psi = new ProcessStartInfo(exe, MpCmd.Args(Kind, Target)) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.Default };
                    p = Process.Start(psi);
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (Lines) Lines.Add(e.Data); };
                    p.BeginErrorReadLine();
                    string line; while ((line = p.StandardOutput.ReadLine()) != null) lock (Lines) Lines.Add(line);
                    p.WaitForExit(); exit = p.ExitCode;
                }
                catch (Exception e) { Error = e.Message; }
                if (cancelled) Result = "cancelled";
                else if (Error != null) Result = "error";
                else
                {
                    int n; List<string> names; lock (Lines) Result = MpCmd.Parse(exit, Lines, out n, out names);
                    Threats = n; Names = names;
                    if (Result == "error") Error = "Defender's scanner stopped with code " + exit + (exit == 5 ? " (it may need admin for this location)" : "") + ".";
                }
                Done = true;
                var f = Finished; if (f != null) f(this);
            }) { IsBackground = true, Name = "scan" }.Start();
        }
        // stops our MpCmdRun and asks Defender to stop the scan it started
        public void Cancel()
        {
            if (Done) return; cancelled = true;
            try { if (p != null && !p.HasExited) p.Kill(); } catch { }
            try { if (exe != null) using (var c = Process.Start(new ProcessStartInfo(exe, "-Cancel") { UseShellExecute = false, CreateNoWindow = true })) c.WaitForExit(10000); } catch { }
        }
        public ScanRecord Record()
        {
            return new ScanRecord { Kind = Kind, Target = Target, Start = Start.ToString("o"), End = DateTime.Now.ToString("o"), Result = Result, Threats = Threats, Note = Result == "threats" ? string.Join(", ", Names) : Error };
        }
    }

    // Watch Downloads: decides when a new file has finished arriving. Seen() is called for file events, Tick() about once a
    // second; Tick returns the files that are ready to scan. Size and clock come in from outside, so the rules can be tested.
    public class DownloadWatcher : IDisposable
    {
        public static readonly string[] PartialExt = { ".crdownload", ".part", ".partial", ".download", ".opdownload", ".tmp", ".temp", ".!ut", ".aria2", ".dtapart" };
        public static bool IsPartial(string path)
        {
            var name = Path.GetFileName(path ?? ""); if (name.Length == 0) return true;
            if (name.StartsWith("~$") || name.StartsWith(".")) return true;
            if (name.StartsWith("Unconfirmed ", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".crdownload", StringComparison.OrdinalIgnoreCase)) return true;
            var ext = Path.GetExtension(name).ToLowerInvariant();
            return PartialExt.Contains(ext) || name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase);
        }

        class Pending { public long Size = -2; public DateTime Changed, FirstSeen; }
        readonly Dictionary<string, Pending> pending = new Dictionary<string, Pending>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, DateTime> recent = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        public TimeSpan Settle = TimeSpan.FromSeconds(3);        // size unchanged this long = finished
        public TimeSpan GiveUp = TimeSpan.FromMinutes(2);        // an empty placeholder that never fills is dropped
        public Func<string, long> SizeOf = DefaultSize;          // -1 = missing or still locked by the browser
        public Func<string, bool> Exists = File.Exists;
        public event Action<string> Ready;

        public static long DefaultSize(string path)
        {
            try
            {
                var fi = new FileInfo(path); if (!fi.Exists) return -1;
                using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) { }   // still being written = can't be opened for reading with only readers allowed
                return fi.Length;
            }
            catch { return -1; }
        }

        public void Seen(string path, DateTime now)
        {
            if (IsPartial(path)) return;
            lock (pending)
            {
                Pending p; if (!pending.TryGetValue(path, out p)) pending[path] = p = new Pending { FirstSeen = now };
                p.Changed = now;
            }
        }
        public int PendingCount { get { lock (pending) return pending.Count; } }

        public List<string> Tick(DateTime now)
        {
            var ready = new List<string>();
            lock (pending)
            {
                foreach (var kv in pending.ToList())
                {
                    var path = kv.Key; var p = kv.Value;
                    if (!Exists(path)) { if ((now - p.Changed) > TimeSpan.FromSeconds(10)) pending.Remove(path); continue; }   // renamed away or deleted
                    if (Exists(path + ".part") || Exists(path + ".crdownload")) { p.Changed = now; continue; }   // Firefox/Chrome still writing next to it
                    var size = SizeOf(path);
                    if (size != p.Size) { p.Size = size; p.Changed = now; continue; }
                    if (size < 0) { if (now - p.FirstSeen > GiveUp) pending.Remove(path); continue; }
                    if (size == 0) { if (now - p.FirstSeen > GiveUp) pending.Remove(path); continue; }   // an empty placeholder
                    if (now - p.Changed < Settle) continue;
                    pending.Remove(path);
                    DateTime last; if (recent.TryGetValue(path, out last) && now - last < TimeSpan.FromMinutes(1)) continue;
                    recent[path] = now; ready.Add(path);
                }
                foreach (var r in recent.Where(x => now - x.Value > TimeSpan.FromMinutes(5)).Select(x => x.Key).ToList()) recent.Remove(r);
            }
            return ready;
        }

        // ---- the real watcher on a folder
        FileSystemWatcher fsw; Timer timer;
        public string Folder { get; private set; }
        public void Start(string folder)
        {
            Stop(); Folder = folder;
            fsw = new FileSystemWatcher(folder) { IncludeSubdirectories = false, NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite, InternalBufferSize = 32768 };
            FileSystemEventHandler h = (s, e) => { if (e.ChangeType != WatcherChangeTypes.Deleted) Seen(e.FullPath, DateTime.Now); };
            fsw.Created += h; fsw.Changed += h; fsw.Renamed += (s, e) => Seen(e.FullPath, DateTime.Now);
            fsw.EnableRaisingEvents = true;
            timer = new Timer(_ => { try { foreach (var f in Tick(DateTime.Now)) { var r = Ready; if (r != null) r(f); } } catch { } }, null, 1000, 1000);
        }
        public void Stop()
        {
            if (fsw != null) { fsw.EnableRaisingEvents = false; fsw.Dispose(); fsw = null; }
            if (timer != null) { timer.Dispose(); timer = null; }
            lock (pending) pending.Clear();
        }
        public void Dispose() { Stop(); }

        [DllImport("shell32.dll")] static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid id, uint flags, IntPtr token, out IntPtr path);
        // the user's Downloads folder (wherever it was moved to)
        public static string DownloadsFolder()
        {
            if (GuardSettings.TestDir != null) return Path.Combine(GuardSettings.TestDir, "Downloads");
            try
            {
                IntPtr p; if (SHGetKnownFolderPath(new Guid("374DE290-123F-4565-9164-39C4925E467B"), 0, IntPtr.Zero, out p) == 0)
                { var s = Marshal.PtrToStringUni(p); Marshal.FreeCoTaskMem(p); if (!string.IsNullOrEmpty(s)) return s; }
            }
            catch { }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        }
    }
}
