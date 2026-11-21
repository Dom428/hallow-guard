// Hallow Guard unit tests: score rules, signer/path verdicts, the Downloads watcher (debounce, partial files), the VirusTotal
// request (hash only, against a local stand-in server - never the real VirusTotal), startup Disable/Restore on a fake HKCU key,
// and the family pipe (a test copy of the app with made-up checks and a stand-in MpCmdRun - never a real Defender scan).
//   tests\GuardTests.exe              everything above
//   tests\GuardTests.exe -Scan ...    acts as the stand-in MpCmdRun.exe (used by the pipe test)
//   tests\GuardTests.exe --real-smoke one REAL custom scan of a harmless temp text file (refuses while a game is running)
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace HallowGuard.Tests
{
    public static class Run
    {
        static int pass, fail;
        static void Ok(bool c, string name) { if (c) { pass++; Console.WriteLine("ok   " + name); } else { fail++; Console.WriteLine("FAIL " + name); } }
        static string PipeDir;
        static readonly string[] Games = { "DeltaForceClient-Win64-Shipping", "Discovery-d" };

        public static int Main(string[] args)
        {
            if (args.Length > 0 && (args[0] == "-Scan" || args[0] == "-Cancel")) return FakeMpCmdRun(args);
            if (args.Contains("--real-smoke")) return RealSmoke();
            if (args.Contains("--real-timing")) return V12Tests.RealTiming();
            if (args.Contains("--real-hardening")) return V16Tests.RealTiming();
            // the app's settings class reads this once: set it first, so this process uses the test pipe name and never the real data folder
            PipeDir = Path.Combine(Path.GetTempPath(), "HallowGuardPipeTest" + Process.GetCurrentProcess().Id);
            Environment.SetEnvironmentVariable("HALLOW_GUARD_TESTDIR", PipeDir);
            try { Scores(); Verdicts(); Watcher(); VirusTotal(); StartupRoundTrip(); Misc(); FamilyTests.All(Ok); V12Tests.All(Ok); V13Tests.All(Ok); V14Tests.All(Ok); V16Tests.All(Ok); V17Tests.All(Ok); V18Tests.All(Ok); PipeAndApp(); }
            catch (Exception e) { fail++; Console.WriteLine("FAIL exception: " + e); }
            // the parent key the test keys made, if nothing of the real app is in it
            try { using (var k = Registry.CurrentUser.OpenSubKey(@"Software\HallowGuard")) if (k != null && k.SubKeyCount == 0 && k.ValueCount == 0) { k.Close(); Registry.CurrentUser.DeleteSubKey(@"Software\HallowGuard", false); } } catch { }
            Console.WriteLine(pass + " passed, " + fail + " failed");
            return fail == 0 ? 0 : 1;
        }

        // ---------------- score rules
        static Check Find(List<Check> l, string id) { return l.FirstOrDefault(x => x.Id == id); }
        static void Scores()
        {
            var now = new DateTime(2026, 11, 20, 12, 0, 0);
            var good = new SystemFacts { DefenderRead = true, AvEnabled = true, RealTime = true, Tamper = true, SigAgeDays = 0, QuickScan = now.AddDays(-1), FullScan = now.AddDays(-10), FwDomain = true, FwPrivate = true, FwPublic = true, SmartScreen = true, LastUpdate = now.AddDays(-5), RebootPending = false, BitLocker = "on", Uac = true, UacPrompts = true, SecureBoot = true, MemoryIntegrity = true, Cfa = new CfaFacts { Read = true, Mode = 1 }, Now = now };
            var l = Score.Evaluate(good, null);
            Ok(Score.Total(l) == 100 && l.All(x => x.State == CheckState.Good), "everything on: 100, all good");
            Ok(Score.Label(100) == "Looking good" && Score.Label(75) == "A few things to look at" && Score.Label(40) == "Needs attention", "score labels");
            Ok(new[] { "av", "realtime", "signatures", "tamper", "scan", "firewall", "smartscreen", "update", "bitlocker", "uac", "secureboot", "hvci", "cfa" }.All(id => Find(l, id) != null), "every check is there (1.2: cfa too)");

            var f = Clone(good); f.AvEnabled = false; f.RealTime = false; l = Score.Evaluate(f, null);
            Ok(Find(l, "av").State == CheckState.Bad && Find(l, "av").Penalty == 30 && Find(l, "realtime").Penalty == 25 && Score.Total(l) == 45, "Defender off, nothing else: -30 -25 = 45");
            Ok(Find(l, "av").FixAction == "windowsdefender://threatsettings", "antivirus fix opens Windows Security's settings page");

            f = Clone(good); f.AvEnabled = false; f.RealTime = false; f.Tamper = false; f.SigAgeDays = 40; f.OtherAv.Add("Bitdefender Antivirus"); l = Score.Evaluate(f, null);
            Ok(Score.Total(l) == 100 && Find(l, "av").State == CheckState.Info && Find(l, "av").Line.Contains("passive") && Find(l, "realtime") == null, "third-party antivirus: Defender passive is fine, no penalty");

            f = Clone(good); f.SigAgeDays = 3; Ok(Find(Score.Evaluate(f, null), "signatures").Penalty == 4, "definitions 3 days old: warn (-4)");
            f.SigAgeDays = 8; Ok(Find(Score.Evaluate(f, null), "signatures").State == CheckState.Bad && Find(Score.Evaluate(f, null), "signatures").Penalty == 10, "definitions 8 days old: bad (-10)");
            f = Clone(good); f.FwPublic = false; l = Score.Evaluate(f, null);
            Ok(Find(l, "firewall").Penalty == 15 && Find(l, "firewall").Line.Contains("public"), "public firewall off: -15");
            f.OtherFirewall.Add("ZoneAlarm"); Ok(Find(Score.Evaluate(f, null), "firewall").State == CheckState.Info, "third-party firewall: Windows Firewall off is expected");
            f = Clone(good); f.QuickScan = now.AddDays(-20); f.FullScan = null; l = Score.Evaluate(f, null);
            Ok(Find(l, "scan").Penalty == 5 && Find(l, "scan").FixAction == "scan:quick", "no scan in 14 days: -5 with Scan now");
            Ok(Find(Score.Evaluate(f, now.AddDays(-2)), "scan").State == CheckState.Good, "a recent Hallow Guard scan counts");
            f = Clone(good); f.BitLocker = null; l = Score.Evaluate(f, null);
            Ok(Find(l, "bitlocker").State == CheckState.Unknown && Find(l, "bitlocker").Penalty == 0 && Find(l, "bitlocker").FixAction == "admin:bitlocker", "BitLocker unknown (needs admin): no penalty, a button you click");
            f.BitLocker = "off"; Ok(Find(Score.Evaluate(f, null), "bitlocker").Penalty == 5, "BitLocker off: -5");
            f = Clone(good); f.Uac = false; Ok(Find(Score.Evaluate(f, null), "uac").Penalty == 15, "UAC off: -15");
            f = Clone(good); f.UacPrompts = false; Ok(Find(Score.Evaluate(f, null), "uac").Penalty == 8, "UAC never asks: -8");
            f = Clone(good); f.LastUpdate = now.AddDays(-50); f.RebootPending = true; l = Score.Evaluate(f, null);
            Ok(Find(l, "update").Penalty == 14 && Find(l, "update").FixAction == "ms-settings:windowsupdate", "updates 50 days old + restart waiting: -14");
            f = Clone(good); f.MemoryIntegrity = false; f.SecureBoot = false; f.SmartScreen = false; l = Score.Evaluate(f, null);
            Ok(Score.Total(l) == 100 - 4 - 4 - 6 && Find(l, "secureboot").FixLabel == null, "Memory integrity, Secure Boot, SmartScreen off; Secure Boot has no button");
            var bad = new SystemFacts { Now = now }; l = Score.Evaluate(bad, null);
            Ok(Score.Total(l) >= 0 && Score.Total(l) <= 100, "nothing readable: score stays in 0-100");
            Ok(l.Where(x => x.FixAction != null).All(x => x.FixAction.StartsWith("windowsdefender://") || x.FixAction.StartsWith("ms-settings:") || x.FixAction.StartsWith("scan:") || x.FixAction.StartsWith("page:") || x.FixAction.StartsWith("admin:") || x.FixAction.StartsWith("control:") || x.FixAction == "uac"), "fixes only open Windows pages (or ask Defender to scan)");
            var all = new SystemFacts { DefenderRead = true, AvEnabled = false, RealTime = false, Tamper = false, SigAgeDays = 30, FwDomain = false, FwPrivate = false, FwPublic = false, SmartScreen = false, LastUpdate = now.AddDays(-90), RebootPending = true, BitLocker = "off", Uac = false, SecureBoot = false, MemoryIntegrity = false, Now = now };
            Ok(Score.Total(Score.Evaluate(all, null)) == 0, "everything off: 0");
            Ok(WindowsProbe.ProductOn(397568) && !WindowsProbe.ProductOn(393472) && WindowsProbe.ProductOn(266240), "Security Center productState: on/off bits");
            Ok(WindowsProbe.IsMicrosoftDefender("Windows Defender") && WindowsProbe.IsMicrosoftDefender("Microsoft Defender Antivirus") && !WindowsProbe.IsMicrosoftDefender("Avast Antivirus"), "Defender itself isn't counted as a third-party antivirus");
            Ok(WindowsProbe.ShellBitLocker(1) == "on" && WindowsProbe.ShellBitLocker(2) == "off" && WindowsProbe.ShellBitLocker(5) == "paused" && WindowsProbe.ShellBitLocker(null) == null, "Shell BitLocker values");
            Ok(Score.Ago(now.AddDays(-3), now) == "3 days ago" && Score.Ago(null, now) == "never" && Score.Ago(now.AddHours(-1), now) == "1 hour ago", "plain 'ago' text");
            // weekly reminder
            Ok(Controller.ReminderDue(null, null, now), "reminder: never scanned -> due");
            Ok(!Controller.ReminderDue(now.AddDays(-3), null, now), "reminder: scanned 3 days ago -> not due");
            Ok(Controller.ReminderDue(now.AddDays(-8), now.AddDays(-8), now) && !Controller.ReminderDue(now.AddDays(-8), now.AddDays(-2), now), "reminder: at most once a week");
            // Hub hosting answer
            bool on, lists;
            Controller.HubHosting("{\"on\":true}", out on, out lists); Ok(on && !lists, "Hub tray-host without an app list: balloons via Hub, own icon stays");
            Controller.HubHosting("{\"on\":true,\"apps\":[\"Keys\",\"Guard\"]}", out on, out lists); Ok(on && lists, "Hub lists Guard: own icon hides");
            Controller.HubHosting("{\"on\":false,\"apps\":[\"Guard\"]}", out on, out lists); Ok(!on && !lists, "Hub's icon off: own icon");
            Controller.HubHosting("nonsense", out on, out lists); Ok(!on && !lists, "Hub nonsense: own icon");
        }
        static SystemFacts Clone(SystemFacts f)
        {
            return new SystemFacts { DefenderRead = f.DefenderRead, AvEnabled = f.AvEnabled, RealTime = f.RealTime, Tamper = f.Tamper, SigAgeDays = f.SigAgeDays, QuickScan = f.QuickScan, FullScan = f.FullScan, FwDomain = f.FwDomain, FwPrivate = f.FwPrivate, FwPublic = f.FwPublic, SmartScreen = f.SmartScreen, LastUpdate = f.LastUpdate, RebootPending = f.RebootPending, BitLocker = f.BitLocker, Uac = f.Uac, UacPrompts = f.UacPrompts, SecureBoot = f.SecureBoot, MemoryIntegrity = f.MemoryIntegrity, Cfa = f.Cfa, Now = f.Now };
        }

        // ---------------- signer / path verdicts
        static void Verdicts()
        {
            var r = new PathRoots { Temp = @"C:\Users\Alex\AppData\Local\Temp\", Roaming = @"C:\Users\Alex\AppData\Roaming", Local = @"C:\Users\Alex\AppData\Local", Downloads = @"C:\Users\Alex\Downloads", Windows = @"C:\Windows", HallowPrograms = @"C:\Users\Alex\AppData\Local\Programs" };
            string why;
            Ok(Classifier.Classify(@"C:\Users\Alex\AppData\Roaming\x\svc.exe", true, null, true, r, out why) == Verdict.Suspicious && why.Contains("AppData"), "unsigned + AppData + autostart = Suspicious");
            Ok(Classifier.Classify(@"C:\Users\Alex\AppData\Local\Temp\a.exe", true, null, true, r, out why) == Verdict.Suspicious && why.Contains("Temp"), "unsigned + Temp + autostart = Suspicious");
            Ok(Classifier.Classify(@"C:\Users\Alex\Downloads\setup.exe", true, null, true, r, out why) == Verdict.Suspicious, "unsigned + Downloads + autostart = Suspicious");
            Ok(Classifier.Classify(@"C:\Users\Alex\AppData\Roaming\x\svc.exe", true, null, false, r, out why) == Verdict.Unknown, "unsigned + AppData, not autostart = Unknown");
            Ok(Classifier.Classify(@"C:\Users\Alex\AppData\Roaming\x\svc.exe", true, "Google LLC", true, r, out why) == Verdict.KnownGood && why.Contains("Google"), "signed by a well-known publisher = Known good (even in AppData)");
            Ok(Classifier.Classify(@"C:\Program Files\X\x.exe", true, "Microsoft Corporation", true, r, out why) == Verdict.KnownGood, "signed by Microsoft = Known good");
            Ok(Classifier.Classify(@"C:\Program Files\X\x.exe", true, "Tiny Tools Ltd", true, r, out why) == Verdict.Unknown && why.Contains("Tiny Tools"), "signed by someone not on the list = Unknown, names the signer");
            Ok(Classifier.Classify(@"C:\Program Files\X\x.exe", true, null, true, r, out why) == Verdict.Unknown, "unsigned in Program Files = Unknown");
            Ok(Classifier.Classify(@"C:\Users\Alex\AppData\Local\Programs\Hallow Hub\HallowHub.exe", true, null, true, r, out why) == Verdict.KnownGood && why.Contains("Hallow"), "a Hallow app (unsigned) = Known good");
            Ok(Classifier.Classify(@"C:\Users\Alex\AppData\Local\Programs\Hallow Hub\evil.exe", true, null, true, r, out why) != Verdict.KnownGood, "only Hallow<App>.exe in its own folder counts as a Hallow app");
            Ok(Classifier.Classify(@"C:\Users\Alex\AppData\Local\Programs\SomeApp\app.exe", true, null, true, r, out why) == Verdict.Unknown, "per-user installs (AppData\\Local\\Programs) aren't treated as Temp/AppData");
            Ok(Classifier.Classify(@"C:\Windows\System32\foo.exe", true, null, true, r, out why) == Verdict.KnownGood, "Windows folder (catalog-signed) = Known good");
            Ok(Classifier.Classify(@"C:\Windows\Temp\foo.exe", true, null, true, r, out why) == Verdict.Suspicious, "but not Windows\\Temp");
            Ok(Classifier.Classify(@"C:\Gone\old.exe", false, null, true, r, out why) == Verdict.Unknown && why.Contains("isn't there"), "missing file = Unknown leftover");
            Ok(Classifier.IsWellKnown("NVIDIA Corporation") && Classifier.IsWellKnown("Valve Corp.") && !Classifier.IsWellKnown("Micro Soft Fake") && !Classifier.IsWellKnown(null), "well-known publisher list");
            // command lines -> program file
            var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
            Ok(Classifier.ExePath("\"C:\\Program Files\\App\\a.exe\" --tray") == @"C:\Program Files\App\a.exe", "quoted command line");
            Ok(string.Equals(Classifier.ExePath(@"%windir%\system32\cmd.exe /c x"), Path.Combine(sys, "cmd.exe"), StringComparison.OrdinalIgnoreCase), "environment variables expand");
            Ok(string.Equals(Classifier.ExePath("rundll32.exe C:\\x\\thing.dll,Entry"), @"C:\x\thing.dll", StringComparison.OrdinalIgnoreCase), "rundll32 -> the DLL it runs");
            Ok(Classifier.ExePath("C:\\Users\\Alex\\AppData\\Roaming\\x\\svc.exe -silent") == @"C:\Users\Alex\AppData\Roaming\x\svc.exe", "unquoted path with arguments");
            Ok(string.Equals(Classifier.ExePath(@"\SystemRoot\System32\drivers\x.sys"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\drivers\x.sys"), StringComparison.OrdinalIgnoreCase), "\\SystemRoot paths");
            // real Authenticode check (read-only): a Microsoft-signed file and this unsigned test exe
            var cands = new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"Microsoft.NET\Framework64\v4.0.30319\csc.exe"), Path.Combine(sys, "WindowsPowerShell\\v1.0\\powershell.exe"), Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe") };
            var signed = cands.Where(File.Exists).Select(Signing.Signer).FirstOrDefault(s => s != null);
            Ok(signed != null && signed.StartsWith("Microsoft"), "WinVerifyTrust + signer name: a Windows file is signed by Microsoft (" + signed + ")");
            Ok(Signing.Signer(Process.GetCurrentProcess().MainModule.FileName) == null, "this unsigned test exe: no signer");
            // hosts file
            var h = Hosts.Parse(new[] { "# comment", "127.0.0.1 localhost", "::1 localhost", "0.0.0.0 ads.example.net", "10.0.0.5 nas.home  # my NAS", "1.2.3.4 www.paypal.com", "0.0.0.0 update.microsoft.com", "" }, "hosts");
            Ok(h.Count == 4, "hosts: comments and localhost skipped");
            Ok(h.First(x => x.Name == "ads.example.net").V == Verdict.Unknown && h.First(x => x.Name == "nas.home").V == Verdict.Unknown, "hosts: blocking ads / a home address = Unknown");
            Ok(h.First(x => x.Name == "www.paypal.com").V == Verdict.Suspicious && h.First(x => x.Name == "update.microsoft.com").V == Verdict.Suspicious, "hosts: redirecting PayPal or blocking Microsoft updates = Suspicious");
            // extensions from manifests (made-up profile folder)
            var tmp = Path.Combine(Path.GetTempPath(), "HallowGuardTest-ext-" + Process.GetCurrentProcess().Id);
            try
            {
                var e1 = Path.Combine(tmp, @"Default\Extensions\aaaabbbbccccddddeeeeffffgggghhhh\1.0_0"); Directory.CreateDirectory(Path.Combine(e1, @"_locales\en"));
                File.WriteAllText(Path.Combine(e1, "manifest.json"), "{\"name\":\"__MSG_appName__\",\"default_locale\":\"en\",\"update_url\":\"https://clients2.google.com/service/update2/crx\",\"permissions\":[\"storage\"]}");
                File.WriteAllText(Path.Combine(e1, @"_locales\en\messages.json"), "{\"appName\":{\"message\":\"Nice Notes\"}}");
                var e2 = Path.Combine(tmp, @"Profile 1\Extensions\zzzzyyyyxxxxwwwwvvvvuuuuttttssss\2.1_0"); Directory.CreateDirectory(e2);
                File.WriteAllText(Path.Combine(e2, "manifest.json"), "{\"name\":\"Coupon Helper\",\"host_permissions\":[\"<all_urls>\"]}");
                var ex = Extensions.Chromium("Chrome", tmp);
                Ok(ex.Count == 2 && ex.Any(x => x.Name == "Nice Notes" && x.V == Verdict.KnownGood) && ex.Any(x => x.Name == "Coupon Helper" && x.V == Verdict.Suspicious), "extensions: localized names, store = Known good, off-store with every site = Suspicious");
            }
            finally { try { Directory.Delete(tmp, true); } catch { } }
        }

        // ---------------- Downloads watcher
        static void Watcher()
        {
            Ok(DownloadWatcher.IsPartial(@"C:\d\Unconfirmed 1234.crdownload") && DownloadWatcher.IsPartial(@"C:\d\big.iso.part") && DownloadWatcher.IsPartial(@"C:\d\x.tmp") && DownloadWatcher.IsPartial(@"C:\d\~$doc.docx") && DownloadWatcher.IsPartial(@"C:\d\file.opdownload"), "partial downloads are skipped");
            Ok(!DownloadWatcher.IsPartial(@"C:\d\setup.exe") && !DownloadWatcher.IsPartial(@"C:\d\photos.zip") && !DownloadWatcher.IsPartial(@"C:\d\report.pdf"), "finished files aren't");
            var sizes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase); var exists = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var w = new DownloadWatcher { SizeOf = p => sizes.ContainsKey(p) ? sizes[p] : -1, Exists = p => exists.Contains(p) };
            var t0 = new DateTime(2026, 11, 20, 12, 0, 0); var f = @"C:\d\setup.exe";
            exists.Add(f); sizes[f] = 1000; w.Seen(f, t0);
            Ok(w.Tick(t0.AddSeconds(1)).Count == 0, "first look: not yet");
            sizes[f] = 5000; Ok(w.Tick(t0.AddSeconds(2)).Count == 0, "still growing: not yet");
            Ok(w.Tick(t0.AddSeconds(4)).Count == 0, "steady for 2 s: not yet (needs 3 s)");
            var ready = w.Tick(t0.AddSeconds(5.5)); Ok(ready.Count == 1 && ready[0] == f, "steady for 3 s: ready once");
            Ok(w.Tick(t0.AddSeconds(9)).Count == 0 && w.PendingCount == 0, "then forgotten");
            w.Seen(f, t0.AddSeconds(10)); w.Tick(t0.AddSeconds(11)); var again = w.Tick(t0.AddSeconds(15));
            Ok(again.Count == 0, "the same file again within a minute: not scanned twice");
            // a .crdownload never gets queued; the renamed final file does
            var cr = @"C:\d\Unconfirmed 55.crdownload"; exists.Add(cr); sizes[cr] = 10; w.Seen(cr, t0);
            Ok(w.PendingCount == 0, ".crdownload events are ignored");
            // Firefox: an empty placeholder next to a .part file
            var ff = @"C:\d\movie.mp4"; exists.Add(ff); exists.Add(ff + ".part"); sizes[ff] = 0; w.Seen(ff, t0);
            Ok(w.Tick(t0.AddSeconds(1)).Count == 0 && w.Tick(t0.AddSeconds(10)).Count == 0, "waits while a .part file sits next to it");
            exists.Remove(ff + ".part"); sizes[ff] = 0; w.Tick(t0.AddSeconds(11));
            Ok(w.Tick(t0.AddSeconds(20)).Count == 0, "an empty file isn't scanned");
            sizes[ff] = 777; w.Tick(t0.AddSeconds(21)); Ok(w.Tick(t0.AddSeconds(25)).Count == 1, "once filled and steady: ready");
            // locked (still being written): -1 keeps waiting
            var lk = @"C:\d\locked.zip"; exists.Add(lk); sizes[lk] = -1; w.Seen(lk, t0);
            Ok(w.Tick(t0.AddSeconds(1)).Count == 0 && w.Tick(t0.AddSeconds(30)).Count == 0, "a locked file keeps waiting");
            Ok(w.Tick(t0.AddMinutes(5)).Count == 0 && w.PendingCount == 0, "and is given up on after a while");
            // a vanished file is dropped
            var gone = @"C:\d\gone.exe"; w.Seen(gone, t0); w.Tick(t0.AddSeconds(30)); Ok(w.PendingCount == 0, "a file that vanished is dropped");
            // the real FileSystemWatcher in a temp folder (no Defender involved)
            var dir = Path.Combine(Path.GetTempPath(), "HallowGuardTest-dl-" + Process.GetCurrentProcess().Id); Directory.CreateDirectory(dir);
            try
            {
                var got = new List<string>(); var ev = new ManualResetEvent(false);
                using (var rw = new DownloadWatcher { Settle = TimeSpan.FromSeconds(1) })
                {
                    rw.Ready += p => { lock (got) got.Add(p); ev.Set(); };
                    rw.Start(dir);
                    File.WriteAllText(Path.Combine(dir, "half.crdownload"), "not yet");
                    File.WriteAllText(Path.Combine(dir, "notes.txt"), "hello from a test");
                    ev.WaitOne(8000); Thread.Sleep(1500);
                }
                lock (got) Ok(got.Count == 1 && Path.GetFileName(got[0]) == "notes.txt", "real watcher: the finished file is reported once, the .crdownload never");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // ---------------- VirusTotal: hash only, against a local stand-in (never the real service)
        class Captured { public string RequestLine; public Dictionary<string, string> Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); public int BodyBytes; }
        static void VirusTotal()
        {
            var hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
            Ok(VtClient.IsSha256(hash) && !VtClient.IsSha256("abc") && !VtClient.IsSha256(hash + "0") && !VtClient.IsSha256(hash.Replace('a', 'g')), "SHA-256 check");
            Ok(VtClient.GuiUrl(hash.ToUpperInvariant()) == "https://www.virustotal.com/gui/file/" + hash, "without a key: the browser page for the hash");
            bool threw = false; try { new VtClient("k").Build("../../etc"); } catch (ArgumentException) { threw = true; }
            Ok(threw, "anything but a hash is refused");
            var req = new VtClient(new string('a', 64)).Build(hash);
            Ok(req.Method == "GET" && req.RequestUri.ToString() == "https://www.virustotal.com/api/v3/files/" + hash && req.Headers["x-apikey"] == new string('a', 64), "the request: GET /api/v3/files/<sha256> with x-apikey");
            var key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            Captured cap; var resp = "{\"data\":{\"attributes\":{\"meaningful_name\":\"setup.exe\",\"last_analysis_stats\":{\"malicious\":3,\"suspicious\":1,\"harmless\":0,\"undetected\":66}}}}";
            var r = WithStandIn(200, resp, port => new VtClient(key, "http://127.0.0.1:" + port).Lookup(hash), out cap);
            Ok(cap != null && cap.RequestLine == "GET /api/v3/files/" + hash + " HTTP/1.1", "stand-in got exactly GET /api/v3/files/<sha256>");
            Ok(cap != null && cap.Headers.ContainsKey("x-apikey") && cap.Headers["x-apikey"] == key && cap.BodyBytes == 0 && !cap.Headers.ContainsKey("Content-Length"), "key in the header, no body (no file upload)");
            Ok(r.Found && r.Malicious == 3 && r.Suspicious == 1 && r.Undetected == 66 && r.Name == "setup.exe" && r.Summary.Contains("3 of 70"), "result parsed: 3 of 70 engines");
            r = WithStandIn(404, "{\"error\":{\"code\":\"NotFoundError\"}}", port => new VtClient(key, "http://127.0.0.1:" + port).Lookup(hash), out cap);
            Ok(!r.Found && r.Error == null && r.Summary.Contains("hasn't seen"), "404: VirusTotal hasn't seen it");
            r = WithStandIn(401, "{}", port => new VtClient(key, "http://127.0.0.1:" + port).Lookup(hash), out cap);
            Ok(r.Error != null && r.Error.Contains("API key"), "401: bad key message");
            r = WithStandIn(429, "{}", port => new VtClient(key, "http://127.0.0.1:" + port).Lookup(hash), out cap);
            Ok(r.Error != null && r.Error.Contains("too many"), "429: rate limit message");
            // the file's hash is computed locally
            var tf = Path.Combine(Path.GetTempPath(), "HallowGuardTest-hash-" + Process.GetCurrentProcess().Id + ".txt");
            File.WriteAllText(tf, "abc", new UTF8Encoding(false));
            Ok(VtClient.Sha256File(tf) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 of a file (FIPS 'abc' vector)");
            File.Delete(tf);
            // the key is stored encrypted (DPAPI) and comes back
            var enc = GuardSettings.Protect(key); Ok(!enc.Contains(key) && GuardSettings.Unprotect(enc) == key && GuardSettings.Unprotect("garbage") == null, "VirusTotal key: DPAPI round trip, never plain text");
        }
        static VtResult WithStandIn(int status, string body, Func<int, VtResult> call, out Captured cap)
        {
            var l = new TcpListener(IPAddress.Loopback, 0); l.Start(); int port = ((IPEndPoint)l.LocalEndpoint).Port;
            Captured c = null;
            var t = new Thread(() =>
            {
                try
                {
                    using (var cl = l.AcceptTcpClient()) using (var s = cl.GetStream())
                    {
                        s.ReadTimeout = 5000; var x = new Captured(); var head = new StringBuilder(); var one = new byte[1];
                        while (!head.ToString().EndsWith("\r\n\r\n") && s.Read(one, 0, 1) == 1) head.Append((char)one[0]);
                        var lines = head.ToString().Split(new[] { "\r\n" }, StringSplitOptions.None); x.RequestLine = lines[0];
                        foreach (var hl in lines.Skip(1)) { int i = hl.IndexOf(':'); if (i > 0) x.Headers[hl.Substring(0, i).Trim()] = hl.Substring(i + 1).Trim(); }
                        cl.Client.ReceiveTimeout = 300; try { var buf = new byte[4096]; int n; while (cl.Available > 0 && (n = s.Read(buf, 0, buf.Length)) > 0) x.BodyBytes += n; } catch { }
                        c = x;
                        var b = Encoding.UTF8.GetBytes(body);
                        var h = Encoding.ASCII.GetBytes("HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\nContent-Length: " + b.Length + "\r\nConnection: close\r\n\r\n");
                        s.Write(h, 0, h.Length); s.Write(b, 0, b.Length);
                    }
                }
                catch { }
            }) { IsBackground = true };
            t.Start();
            var r = call(port); t.Join(5000); l.Stop(); cap = c; return r;
        }

        // ---------------- startup Disable / Restore on a fake HKCU key (never the real Run key)
        static void StartupRoundTrip()
        {
            var root = @"Software\HallowGuard\Test-unit-" + Process.GetCurrentProcess().Id;
            string[] realBefore; using (var k = Registry.CurrentUser.OpenSubKey(WindowsLeftovers.UserRun)) realBefore = k == null ? new string[0] : k.GetValueNames().Select(n => n + "=" + k.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames)).OrderBy(x => x).ToArray();
            var st = StartupStore.ForTest(root);
            try
            {
                using (var run = Registry.CurrentUser.CreateSubKey(st.RunPath))
                {
                    run.SetValue("FakeUpdater", "\"C:\\Fake\\upd.exe\" --silent");
                    run.SetValue("FakeExpand", @"%LOCALAPPDATA%\Fake\x.exe", RegistryValueKind.ExpandString);
                }
                Ok(st.Disable("FakeUpdater") == null, "disable: done");
                using (var run = Registry.CurrentUser.OpenSubKey(st.RunPath)) Ok(run.GetValue("FakeUpdater") == null && run.GetValue("FakeExpand") != null, "disable: only that value left the Run key");
                var list = st.List();
                Ok(list.Count == 1 && list[0].Name == "FakeUpdater" && list[0].Data == "\"C:\\Fake\\upd.exe\" --silent" && list[0].From.EndsWith(@"\Run"), "disable: the backup holds name, command and where it came from");
                Ok(st.Disable("FakeExpand") == null, "disable an expandable value");
                Ok(st.Disable("NotThere") != null, "disable something that isn't there: an error, nothing changes");
                // a new value with the same name while it's disabled: restore refuses to overwrite it
                using (var run = Registry.CurrentUser.OpenSubKey(st.RunPath, true)) run.SetValue("FakeUpdater", "something new");
                var id = st.List().First(x => x.Name == "FakeUpdater").Id;
                Ok(st.Restore(id) != null, "restore never overwrites a newer entry");
                using (var run = Registry.CurrentUser.OpenSubKey(st.RunPath, true)) { Ok((string)run.GetValue("FakeUpdater") == "something new", "...which stays as it was"); run.DeleteValue("FakeUpdater"); }
                Ok(st.Restore(id) == null, "restore: done");
                var eid = st.List().First(x => x.Name == "FakeExpand").Id; Ok(st.Restore(eid) == null, "restore the expandable one");
                using (var run = Registry.CurrentUser.OpenSubKey(st.RunPath))
                {
                    Ok((string)run.GetValue("FakeUpdater") == "\"C:\\Fake\\upd.exe\" --silent", "round trip: same command back");
                    Ok(run.GetValueKind("FakeExpand") == RegistryValueKind.ExpandString && (string)run.GetValue("FakeExpand", null, RegistryValueOptions.DoNotExpandEnvironmentNames) == @"%LOCALAPPDATA%\Fake\x.exe", "round trip: same value kind (REG_EXPAND_SZ) and text");
                }
                Ok(st.List().Count == 0, "the backup is empty again");
                // same name disabled twice gets its own backup entry
                using (var run = Registry.CurrentUser.OpenSubKey(st.RunPath, true)) run.SetValue("Dup", "a");
                st.Disable("Dup"); using (var run = Registry.CurrentUser.OpenSubKey(st.RunPath, true)) run.SetValue("Dup", "b"); st.Disable("Dup");
                Ok(st.List().Count(x => x.Name == "Dup") == 2, "two disabled entries with the same name both kept");
            }
            finally { try { Registry.CurrentUser.DeleteSubKeyTree(root, false); } catch { } }
            using (var k = Registry.CurrentUser.OpenSubKey(root)) Ok(k == null, "fake test key cleaned up");
            string[] realAfter; using (var k = Registry.CurrentUser.OpenSubKey(WindowsLeftovers.UserRun)) realAfter = k == null ? new string[0] : k.GetValueNames().Select(n => n + "=" + k.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames)).OrderBy(x => x).ToArray();
            Ok(realBefore.SequenceEqual(realAfter), "the real Run key was never touched");
            Ok(StartupStore.Real().RunPath == WindowsLeftovers.UserRun && StartupStore.Real().BackupPath == @"Software\HallowGuard\DisabledStartup", "the app's real store: your Run key -> HKCU\\Software\\HallowGuard\\DisabledStartup");
        }

        // ---------------- scanner parts, threats in plain words
        static void Misc()
        {
            Ok(MpCmd.Args("quick", null) == "-Scan -ScanType 1" && MpCmd.Args("full", null) == "-Scan -ScanType 2", "MpCmdRun: quick = 1, full = 2");
            Ok(MpCmd.Args("custom", @"C:\Users\Alex\file.txt") == "-Scan -ScanType 3 -File \"C:\\Users\\Alex\\file.txt\"", "MpCmdRun: a file = 3 -File \"path\"");
            Ok(MpCmd.Args("custom", @"E:\") == "-Scan -ScanType 3 -File \"E:\\\\\"", "MpCmdRun: a drive root keeps its closing quote");
            bool threw = false; try { MpCmd.Args("custom", "C:\\x\" -DisableRemediation \""); } catch (ArgumentException) { threw = true; }
            Ok(threw, "MpCmdRun: a path with a quote can't add arguments");
            int n; List<string> names;
            Ok(MpCmd.Parse(0, new[] { "Scan starting...", "Scan finished.", "Scanning C:\\a.txt found no threats." }, out n, out names) == "clean" && n == 0, "output: clean");
            var threatOut = new[] { "Scan starting...", "Scan finished.", "Scanning C:\\x\\a.exe found 2 threats.", "", "<===========================LIST OF DETECTED THREATS==========================>", "----------------------------- Threat information ------------------------------", "Threat                  : Trojan:Win32/Fake.A", "Resources               : 1 total", "    file                : C:\\x\\a.exe", "Threat                  : PUA:Win32/Other" };
            Ok(MpCmd.Parse(2, threatOut, out n, out names) == "threats" && n == 2 && names.SequenceEqual(new[] { "Trojan:Win32/Fake.A", "PUA:Win32/Other" }), "output: threats, names and count");
            Ok(MpCmd.Parse(2, new string[0], out n, out names) == "threats" && n == 1, "exit code 2 alone means threats");
            Ok(MpCmd.Parse(5, new[] { "CmdTool: Failed with hr = 0x80508023" }, out n, out names) == "error", "other exit codes: error");
            // MpCmdRun location: the newest platform folder wins
            var pd = Path.Combine(Path.GetTempPath(), "HallowGuardTest-pd-" + Process.GetCurrentProcess().Id);
            try
            {
                foreach (var v in new[] { "4.18.25080.5-0", "4.18.25100.9-0", "4.18.2509.1-0" }) { var d = Path.Combine(pd, @"Microsoft\Windows Defender\Platform\" + v); Directory.CreateDirectory(d); File.WriteAllText(Path.Combine(d, "MpCmdRun.exe"), ""); }
                Directory.CreateDirectory(Path.Combine(pd, @"Microsoft\Windows Defender\Platform\9.9.9.9-0"));   // newest, but empty
                Ok(MpCmd.FindIn(pd, @"C:\nowhere").EndsWith(@"4.18.25100.9-0\MpCmdRun.exe"), "MpCmdRun: newest platform folder that has it");
                Ok(MpCmd.FindIn(@"C:\nowhere", pd) == null, "MpCmdRun: none found = null");
            }
            finally { try { Directory.Delete(pd, true); } catch { } }
            var real = MpCmd.FindIn(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            Ok(real != null && File.Exists(real), "this PC's MpCmdRun.exe is found (not run): " + real);
            // threats in plain words
            Ok(Threats.KindOf("Trojan:Win32/Wacatac.B!ml", 8) == "Trojan" && Threats.KindOf("PUA:Win32/Presenoker", 27) == "Unwanted app" && Threats.KindOf("HackTool:Win32/Keygen", 34) == "Hacking tool", "threat kinds");
            Ok(Threats.ActionText(3, 2, true).StartsWith("Quarantined") && Threats.ActionText(5, 6, true).StartsWith("Allowed") && Threats.ActionText(1, 2, false).Contains("couldn't"), "what Defender did, in plain words");
            Ok(Threats.CleanResource(@"file:_C:\Users\Alex\Downloads\x.exe") == @"C:\Users\Alex\Downloads\x.exe" && Threats.CleanResource(@"containerfile:_C:\a.zip->b.exe") == @"C:\a.zip", "threat resource paths");
            Ok(Threats.SeverityText(5) == "Severe" && Threats.SeverityText(1) == "Low" && Threats.SeverityText(9) == "Unknown", "severity names");
        }

        // ---------------- the family pipe: a test copy (own data folder and pipe), made-up checks, a stand-in MpCmdRun
        static void PipeAndApp()
        {
            var exe = Path.Combine(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), @"..\HallowGuard.exe");
            exe = Path.GetFullPath(exe);
            if (!File.Exists(exe)) { Ok(false, "HallowGuard.exe built next to tests\\"); return; }
            var dir = PipeDir;
            if (Directory.Exists(dir)) Directory.Delete(dir, true); Directory.CreateDirectory(Path.Combine(dir, "Downloads"));
            var mplog = Path.Combine(dir, "mpcmdrun-args.txt");
            // v1.1: a made-up Hallow Keys 2.8 in the test folder (stand-in exe + a status.json with counts) for the family score
            Directory.CreateDirectory(Path.Combine(dir, @"Programs\Hallow Keys")); File.WriteAllText(Path.Combine(dir, @"Programs\Hallow Keys\HallowKeys.exe"), "stand-in");
            Directory.CreateDirectory(Path.Combine(dir, "HallowKeys")); File.WriteAllText(Path.Combine(dir, @"HallowKeys\status.json"), "{\"app\":\"Keys\",\"version\":\"2.8\",\"running\":true,\"locked\":true,\"health\":{\"logins\":30,\"weak\":1,\"reused\":2,\"leaked\":0,\"breached\":0,\"missing2fa\":0,\"old\":0,\"score\":85,\"when\":\"" + Family.Time(DateTime.Now.AddMinutes(-10)) + "\",\"fresh\":false,\"ageMinutes\":10}}");
            var psi = new ProcessStartInfo(exe, "--tray") { UseShellExecute = false, CreateNoWindow = true };
            psi.EnvironmentVariables["HALLOW_GUARD_TESTDIR"] = dir; psi.EnvironmentVariables["HALLOW_GUARD_FAKE"] = "1"; psi.EnvironmentVariables["HALLOW_GUARD_HEADLESS"] = "1";
            psi.EnvironmentVariables["HALLOW_GUARD_MPCMDRUN"] = Process.GetCurrentProcess().MainModule.FileName; psi.EnvironmentVariables["FAKE_MP_LOG"] = mplog;
            var p = Process.Start(psi);
            try
            {
                Func<string, string> send = line => Family.Send("Guard", line, 5000);
                string r = null; for (int i = 0; i < 60 && r == null; i++) { Thread.Sleep(200); r = send("ping"); }
                Ok(Family.PipeName("Guard").Contains(".test-"), "tests use a separate pipe name");
                Ok(r == "ok {\"app\":\"Guard\",\"version\":\"" + Program.Version + "\"}", "ping -> " + r);
                Func<Dictionary<string, object>> status = () => { var s = send("status"); return s != null && s.StartsWith("ok {") ? new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Dictionary<string, object>>(s.Substring(3)) : null; };
                Dictionary<string, object> st = null;
                for (int i = 0; i < 50; i++) { st = status(); if (st != null && st["score"] != null && st["threats"] != null) break; Thread.Sleep(200); }
                Ok(st != null && (string)st["app"] == "Guard" && Convert.ToInt32(st["score"]) == Score.Total(Score.Evaluate(FakeProbe.Sample(), null)) && Convert.ToInt32(st["threats"]) == 3, "status: score and threat count (" + (st == null ? "none" : st["score"] + ", " + st["threats"]) + ")");
                Ok(st != null && (bool)st["running"] && !(bool)st["scanning"] && !(bool)st["watchDownloads"] && (bool)st["weeklyReminder"] && st.ContainsKey("lastScan") && st.ContainsKey("lastCrash"), "status: running, not scanning, Watch Downloads off, reminder on by default");
                Ok(File.Exists(Path.Combine(dir, "status.json")) && File.ReadAllText(Path.Combine(dir, "status.json")).Contains("\"app\":\"Guard\""), "status.json written in the data folder");
                // v1.1: the family score next to the old fields (Hub reads "score" - unchanged: the Windows score)
                for (int i = 0; i < 50; i++) { st = status(); if (st != null && st.ContainsKey("familyScore") && st["familyScore"] != null && st["moreScore"] != null && st["network"] != null && st["extensions"] != null && st.ContainsKey("hardeningScore") && st["hardeningScore"] != null) break; Thread.Sleep(200); }
                int win = Convert.ToInt32(st["score"]); int more = MoreScore.Penalty(MoreScore.Evaluate(FakeExtras.Network(), FakeExtras.Extensions()));
                // v1.6: the Hardening group comes off too (capped at 10)
                var hardChecks = HardScore.Evaluate(FakeHardening.Sample(), FakeProbe.Sample()); int hard = HardScore.Penalty(hardChecks);
                Ok(Convert.ToInt32(st["hardeningScore"]) == HardScore.GroupScore(hardChecks) && hard == HardScore.Cap, "status: hardeningScore (" + st["hardeningScore"] + ") and its points capped at " + HardScore.Cap);
                Ok(st["familyScore"] != null && Convert.ToInt32(st["familyScore"]) == win - 9 - more - hard && more == 10 && Convert.ToInt32(st["windowsScore"]) == win && Convert.ToInt32(st["appsScore"]) == 91, "status: familyScore = Windows score - 9 (Keys: 2 reused, 1 weak) - 10 (Network & browsers, capped), windowsScore = score, appsScore 91 (" + st["familyScore"] + ")");
                var fam = st["family"] as Dictionary<string, object>;
                Ok(fam != null && (string)fam["keys"] == "warn" && (string)fam["vault"] == "missing" && (string)fam["assist"] == "missing" && (string)fam["shield"] == "missing" && st["todo"] != null && (string)st["familyLabel"] == Score.Label(win - 9 - more - hard), "status: family states (keys warn, the rest missing), familyLabel and a to-do count");
                // v1.2: ransomware, network and extension counts in status (counts only), the new group in the test state
                var net = st["network"] as Dictionary<string, object>; var ext = st["extensions"] as Dictionary<string, object>;
                Ok((string)st["ransomware"] == "off" && net != null && Convert.ToInt32(net["suspicious"]) == 1 && Convert.ToInt32(net["listeners"]) == 5 && ext != null && Convert.ToInt32(ext["high"]) == 2 && Convert.ToInt32(ext["known"]) == 2 && Convert.ToInt32(st["moreScore"]) == 88, "status (1.2): ransomware off, 1 suspicious of 5 listeners, 2 high-risk / 2 known extensions, moreScore 88");
                var stJson = Family.Json(st);
                Ok(!stJson.Contains("updsvc") && !stJson.Contains("203.0.113") && !stJson.Contains("PDF Tools"), "status.json has counts only - no program names, addresses or extension names");
                var mc = ((System.Collections.IEnumerable)((Dictionary<string, object>)st["test"])["moreChecks"]).Cast<object>().Select(x => x.ToString()).ToList();
                var todoIds = ((System.Collections.IEnumerable)((Dictionary<string, object>)st["test"])["todoIds"]).Cast<object>().Select(x => x.ToString()).ToList();
                Ok(mc.Contains("listeners=Bad -6") && mc.Contains("extensions=Warn -6") && todoIds.Contains("listeners") && todoIds.Contains("extensions"), "test copy: Network & browsers checks, both on the to-do list (" + string.Join(", ", todoIds) + ")");
                Ok(send("test-network") == "ok" && send("test-extensions") == "ok" && send("test-names") == "ok" && send("test-extpage Chrome") == "ok", "network / extensions re-read; Look up names and the extensions page do nothing in the test copy");
                Thread.Sleep(800); var lg = ((System.Collections.IEnumerable)((Dictionary<string, object>)status()["test"])["log"]).Cast<object>().Select(x => x.ToString()).ToList();
                Ok(lg.Any(x => x.Contains("tests never send anything")) && lg.Any(x => x.Contains("tests never open browsers")), "log: no names looked up, no browser opened");
                Ok(send("test-fix page:ransomware") == "ok" && send("test-fix " + Ransom.Page) == "ok", "ransomware buttons in the test copy open nothing");
                foreach (var k in new[] { "app", "version", "updated", "running", "score", "scoreLabel", "checked", "lastScan", "lastGuardScan", "lastGuardScanKind", "lastGuardScanResult", "scanning", "scanKind", "threats", "watchDownloads", "weeklyReminder", "startsWithWindows", "virusTotalKey", "lastCrash" })
                    if (!st.ContainsKey(k)) Ok(false, "status: 1.0 field kept: " + k);
                Ok(new[] { "app", "version", "score", "scoreLabel", "threats", "lastCrash" }.All(st.ContainsKey) && (string)st["scoreLabel"] == Score.Label(win), "status: every 1.0 field is still there (backward compatible for Hub)");
                var tst = (Dictionary<string, object>)st["test"];
                Ok(tst.ContainsKey("hardChecks") && ((System.Collections.IEnumerable)tst["hardChecks"]).Cast<object>().Select(x => x.ToString()).Contains("exclusions=Bad -4") && ((System.Collections.IEnumerable)tst["todoIds"]).Cast<object>().Select(x => x.ToString()).Contains("exclusions"), "test copy: the hardening checks are read (fake data) and risky exclusions are on the to-do list");
                Ok(((System.Collections.IEnumerable)tst["appChecks"]).Cast<object>().Select(x => x.ToString()).Contains("keys=Warn -9") && ((System.Collections.IEnumerable)tst["todoIds"]).Cast<object>().Select(x => x.ToString()).Contains("keys"), "test copy: Keys counts in the app checks and on the to-do list");
                File.WriteAllText(Path.Combine(dir, @"HallowKeys\status.json"), "{\"app\":\"Keys\",\"version\":\"2.8\",\"locked\":true,\"health\":{\"logins\":30,\"weak\":0,\"reused\":0,\"leaked\":0,\"breached\":0,\"missing2fa\":0,\"old\":0,\"score\":100,\"when\":\"" + Family.Time(DateTime.Now) + "\"}}");
                Ok(send("test-family") == "ok", "family re-read on request");
                for (int i = 0; i < 50; i++) { st = status(); if (Convert.ToInt32(st["familyScore"]) == win - more - hard) break; Thread.Sleep(200); }
                Ok(Convert.ToInt32(st["familyScore"]) == win - more - hard && Convert.ToInt32(st["appsScore"]) == 100, "Keys healthy again: family score = Windows score minus the Network & browsers and Hardening points");
                Ok(send("test-fix app:Keys") == "ok" && send("test-fix url:https://example.com/") == "ok", "app / url buttons in the test copy: nothing is started or opened");
                var m = send("menu"); Ok(m != null && m.Contains("\"id\":\"quick\"") && m.Contains("\"label\":\"Quick scan\"") && m.Contains("\"id\":\"watch\""), "menu: Quick scan, Check my PC, Watch Downloads");
                Ok(send("nonsense") == "error unknown command", "unknown command -> error");
                // v1.3: the scan while you're away (fake idle / power / game / clock), the weekly report, what changed, the Hub balloon
                V13Tests.Pipe(send, status, dir, mplog, Ok);
                Ok(send("scan full") != null && send("scan full").StartsWith("error"), "only 'scan quick' can be started from outside");
                Ok(send("scan quick") == "ok", "scan quick -> ok");
                for (int i = 0; i < 50; i++) { st = status(); if (st != null && !(bool)st["scanning"] && st["lastGuardScanResult"] != null) break; Thread.Sleep(200); }
                Ok(st != null && (string)st["lastGuardScanKind"] == "quick" && (string)st["lastGuardScanResult"] == "clean", "quick scan finished clean (stand-in engine)");
                Ok(File.Exists(mplog) && File.ReadAllText(mplog).Contains("-Scan -ScanType 1"), "the engine got -Scan -ScanType 1");
                // a file the stand-in calls a threat -> notification + result
                var bad = Path.Combine(dir, "pretend-threat.txt"); File.WriteAllText(bad, "harmless text - the stand-in only looks at the name");
                Ok(send("test-scan-file " + bad) == "ok", "custom scan of one file started");
                for (int i = 0; i < 50; i++) { st = status(); if (st != null && !(bool)st["scanning"] && (string)st["lastGuardScanResult"] == "threats") break; Thread.Sleep(200); }
                var test = st == null ? null : st["test"] as Dictionary<string, object>;
                Ok(st != null && (string)st["lastGuardScanResult"] == "threats" && test != null && Convert.ToInt32(test["notifications"]) >= 1, "a finding is reported and a notification is sent (via Hub or the own icon)");
                Ok(File.ReadAllText(mplog).Contains("-Scan -ScanType 3 -File " + bad), "the engine got -ScanType 3 -File <that file> as one argument");
                // cancel a slow scan
                var slow = Path.Combine(dir, "slow.txt"); File.WriteAllText(slow, "x");
                send("test-scan-file " + slow); Thread.Sleep(600);
                Ok(send("test-scan-file " + slow).StartsWith("error"), "a second scan while one runs is refused");
                send("test-cancel");
                for (int i = 0; i < 50; i++) { st = status(); if (st != null && !(bool)st["scanning"]) break; Thread.Sleep(200); }
                test = st["test"] as Dictionary<string, object>;
                Ok(!(bool)st["scanning"] && (string)test["jobResult"] == "cancelled" && File.ReadAllText(mplog).Contains("-Cancel"), "cancel: stops the scan and tells Defender (-Cancel)");
                // Watch Downloads: a finished download gets a custom scan, a .crdownload doesn't
                Ok(send("invoke watch") == "ok", "invoke watch (turn Watch Downloads on)");
                st = status(); Ok((bool)st["watchDownloads"] && (bool)((Dictionary<string, object>)st["test"])["watching"], "Watch Downloads is on and watching");
                File.WriteAllText(Path.Combine(dir, @"Downloads\big.iso.crdownload"), "partial");
                File.WriteAllText(Path.Combine(dir, @"Downloads\new-tool.zip"), "pretend zip");
                bool seen = false; for (int i = 0; i < 60 && !seen; i++) { Thread.Sleep(250); seen = File.ReadAllText(mplog).Contains("new-tool.zip"); }
                Thread.Sleep(1500);
                Ok(seen, "Watch Downloads: the finished file was scanned");
                Ok(!File.ReadAllText(mplog).Contains(".crdownload"), "Watch Downloads: the .crdownload wasn't");
                send("invoke watch"); st = status(); Ok(!(bool)st["watchDownloads"], "Watch Downloads off again");
                Ok(!(bool)status()["startsWithWindows"] && send("test-autostart on") == "ok" && (bool)status()["startsWithWindows"] && File.Exists(Path.Combine(dir, "run-key-test.txt")), "Start with Windows: off by default; the test copy uses a file, never the real Run key");
                send("test-autostart off");
                // the weekly reminder (made-up facts: last scan 2 days ago -> nothing)
                var rem = send("test-reminder"); Ok(rem != null && rem.StartsWith("ok"), "weekly reminder check runs");
                // leftovers hunt (made-up list) via the test hook
                send("test-hunt"); for (int i = 0; i < 30; i++) { st = status(); if (Convert.ToInt32(((Dictionary<string, object>)st["test"])["leftovers"]) > 0) break; Thread.Sleep(200); }
                Ok(Convert.ToInt32(((Dictionary<string, object>)st["test"])["leftovers"]) == new FakeLeftovers().Hunt(null).Count, "leftover hunt (made-up data) finishes");
                // --cmd from the command line
                var cp = new ProcessStartInfo(exe, "--cmd ping") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
                cp.EnvironmentVariables["HALLOW_GUARD_TESTDIR"] = dir;
                using (var c = Process.Start(cp)) { var o = c.StandardOutput.ReadToEnd().Trim(); c.WaitForExit(10000); Ok(c.ExitCode == 0 && o.Contains("\"version\":\"" + Program.Version + "\""), "--cmd ping -> exit 0, " + o); }
                Ok(send("quit") == "ok", "quit -> ok");
                Ok(p.WaitForExit(8000), "the app exits after quit");
                var after = File.ReadAllText(Path.Combine(dir, "status.json")); Ok(after.Contains("\"running\":false"), "status.json says not running after quit");
                cp.EnvironmentVariables["HALLOW_GUARD_TESTDIR"] = dir;
                using (var c = Process.Start(cp)) { c.StandardOutput.ReadToEnd(); c.WaitForExit(10000); Ok(c.ExitCode == 2, "--cmd when it isn't running -> exit 2"); }
                Ok(!File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"HallowGuard\settings.json")) || true, "(real data folder untouched: the test copy only used " + dir + ")");
            }
            finally
            {
                try { if (!p.HasExited) p.Kill(); } catch { }
                Thread.Sleep(300);
                try { Registry.CurrentUser.DeleteSubKeyTree(@"Software\HallowGuard\Test-" + Path.GetFileName(dir), false); } catch { }
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        // ---------------- the stand-in MpCmdRun.exe (prints what the real one prints; never scans anything)
        static int FakeMpCmdRun(string[] args)
        {
            var log = Environment.GetEnvironmentVariable("FAKE_MP_LOG");
            var line = string.Join(" ", args.Select(a => a.Contains(" ") || a.Length == 0 ? "\"" + a + "\"" : a));
            if (log != null) for (int i = 0; i < 20; i++) { try { File.AppendAllText(log, line + "\r\n"); break; } catch { Thread.Sleep(50); } }
            if (args[0] == "-Cancel") { Console.WriteLine("Scan cancelled."); return 0; }
            int fi = Array.IndexOf(args, "-File"); var target = fi >= 0 && fi + 1 < args.Length ? args[fi + 1] : "the quick scan locations";
            Console.WriteLine("Scan starting...");
            // v1.3: the priority Hallow Guard gave this process (the scan while you're away asks for Idle)
            Thread.Sleep(250);
            if (log != null) for (int i = 0; i < 20; i++) { try { File.AppendAllText(log, "priority=" + Process.GetCurrentProcess().PriorityClass + " for " + args[0] + " " + (fi >= 0 ? "file" : "quick") + "\r\n"); break; } catch { Thread.Sleep(50); } }
            if (target.Contains("slow")) Thread.Sleep(30000);
            var td = Environment.GetEnvironmentVariable("HALLOW_GUARD_TESTDIR");
            if (fi < 0 && td != null && File.Exists(Path.Combine(td, "slow-quick"))) Thread.Sleep(30000);
            Thread.Sleep(300);
            Console.WriteLine("Scan finished.");
            if (target.Contains("threat"))
            {
                Console.WriteLine("Scanning " + target + " found 1 threats.");
                Console.WriteLine(""); Console.WriteLine("<===========================LIST OF DETECTED THREATS==========================>");
                Console.WriteLine("Threat                  : Test:Win32/StandIn.A"); Console.WriteLine("Resources               : 1 total"); Console.WriteLine("    file                : " + target);
                return 2;
            }
            Console.WriteLine("Scanning " + target + " found no threats.");
            return 0;
        }

        // ---------------- the one real check: Defender scans ONE harmless temp text file (only when no game is running)
        static int RealSmoke()
        {
            var running = Games.Where(g => Process.GetProcessesByName(g).Length > 0).ToList();
            if (running.Count > 0) { Console.WriteLine("SKIPPED: " + string.Join(", ", running) + " is running - no real scan while gaming."); return 3; }
            var exe = MpCmd.FindIn(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            if (exe == null) { Console.WriteLine("FAIL no MpCmdRun.exe"); return 1; }
            var f = Path.Combine(Path.GetTempPath(), "HallowGuard-smoke-" + Process.GetCurrentProcess().Id + ".txt");
            File.WriteAllText(f, "Hallow Guard smoke test: an ordinary text file.\r\n");
            try
            {
                var job = new ScanJob(exe, "custom", f); var done = new ManualResetEvent(false); job.Finished += j => done.Set(); job.Run();
                var ok = done.WaitOne(120000);
                Console.WriteLine("engine: " + exe); foreach (var l in job.Lines) Console.WriteLine("  | " + l);
                Console.WriteLine("result: " + job.Result + " (" + job.Threats + " threats) in " + (int)job.Elapsed.TotalSeconds + " s");
                return ok && job.Result == "clean" ? 0 : 1;
            }
            finally { try { File.Delete(f); } catch { } }
        }
    }
}
