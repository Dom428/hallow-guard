// Hallow Guard - a friendly safety center on top of Microsoft Defender: a safety score, scans through Defender's own engine,
// Defender's threat history in plain words, a leftover hunt and an optional VirusTotal second opinion (hash only).
// It is NOT an antivirus of its own and never disables, replaces or weakens Defender. It never changes a security setting
// by itself: fixes open the right Windows page, and the one admin action runs only when you click it (Windows asks first).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Threading;
using WF = System.Windows.Forms;

[assembly: AssemblyTitle("Hallow Guard")]
[assembly: AssemblyProduct("Hallow Guard")]
[assembly: AssemblyDescription("A friendly safety center on top of Microsoft Defender")]
[assembly: AssemblyVersion("1.9.0.0")]
[assembly: AssemblyFileVersion("1.9.0.0")]

namespace HallowGuard
{
    public static class Program
    {
        public const string Version = "1.9";
        [DllImport("user32.dll")] static extern bool SetProcessDpiAwarenessContext(IntPtr v);

        [STAThread]
        public static void Main(string[] args)
        {
            int ci = Array.IndexOf(args, "--cmd");
            if (ci >= 0) { Environment.Exit(Family.RunCmd(ci + 1 < args.Length ? args[ci + 1] : "")); return; }
            try { SetProcessDpiAwarenessContext(new IntPtr(-4)); } catch { }
            int si = Array.IndexOf(args, "--snap");
            if (si >= 0 && si + 1 < args.Length)
            {
                Snap.On = true; GuardSettings.Frozen = true;
                var sa = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown }; LoadTheme(sa);
                SnapAll(args[si + 1]); return;
            }
            var leaf = GuardSettings.TestDir != null ? "Test" + Path.GetFileName(GuardSettings.TestDir.TrimEnd('\\')) : "";
            bool created;
            var mutex = new Mutex(true, @"Local\HallowGuard" + leaf, out created);
            var showEvent = new EventWaitHandle(false, EventResetMode.AutoReset, @"Local\HallowGuardShow" + leaf);
            if (!created) { showEvent.Set(); return; }
            Crash.Install();
            var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown }; LoadTheme(app);
            app.DispatcherUnhandledException += (s, e) => { Crash.Write(e.Exception); e.Handled = true; Environment.Exit(1); };
            var c = new Controller(args.Contains("--tray"));
            new Thread(() => { while (showEvent.WaitOne()) app.Dispatcher.BeginInvoke(new Action(() => c.ShowMain(null))); }) { IsBackground = true }.Start();
            app.Run();
            GC.KeepAlive(mutex);
        }
        public static string AccentHex = Accent.Default;
        // look: "console" / "classic" / "cyberblue", or null = the one in Settings. A HUD look's dictionary goes over the classic
        // one (same keys win). v1.7: Hallow console gets the Hallow accent swapped in, like the classic theme; Cyber blue never does.
        // v1.8: light: null = from the settings + theme.json + Windows (Mode.Resolve); --snap forces it. Cyber blue is always dark.
        public static string TextAccentHex = Accent.Default;
        public static void LoadTheme(Application app, string look = null, bool? light = null)
        {
            var st = GuardSettings.Load();
            AccentHex = Accent.Current(st.UseHallowAccent);
            HallowGuard.Look.Current = HallowGuard.Look.Normalize(look ?? st.Look);
            Mode.IsLight = !HallowGuard.Look.IsCyberBlue && (light ?? Mode.Resolve(HallowGuard.Look.Current, st.Mode, Accent.ReadMode(), Mode.Sys));
            TextAccentHex = Mode.IsLight ? Mode.TextAccent(AccentHex) : AccentHex;
            Hud.Use(HallowGuard.Look.Current, AccentHex);
            app.Resources.MergedDictionaries.Clear();
            var classic = Res("HallowGuard.Theme.xaml");
            if (Mode.IsLight) classic = Mode.LightClassic(classic, TextAccentHex, AccentHex);
            app.Resources.MergedDictionaries.Add((ResourceDictionary)XamlReader.Parse(Accent.ApplyTo(classic, AccentHex)));
            if (HallowGuard.Look.IsCyberBlue) app.Resources.MergedDictionaries.Add((ResourceDictionary)XamlReader.Parse(Res("HallowGuard.ThemeCyber.xaml")));
            else if (HallowGuard.Look.IsHud) app.Resources.MergedDictionaries.Add((ResourceDictionary)XamlReader.Parse(ConsoleTheme(Mode.IsLight ? AccentHex : Hud.GlowHex)));
        }
        // the Hallow console dictionary with the accent swapped in (dark: the readable accent - a very dark one is lightened;
        // v1.8 light: the real accent for fills and tints, the darkened one for text and thin lines)
        public static string ConsoleTheme(string accent)
        {
            var x = Res("HallowGuard.ThemeConsole.xaml");
            if (Mode.IsLight) x = Mode.LightConsole(x, Mode.TextAccent(accent), accent);
            return Accent.ApplyTo(x, accent);
        }
        static string Res(string name) { using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) using (var r = new StreamReader(s)) return r.ReadToEnd(); }

        // --snap <folder>: every page rendered off-screen with made-up data (never this PC's real files, names or settings)
        // v1.7: every look - Hallow console (the default) in the folder itself, Hallow classic in <folder>\classic, Cyber blue in
        // <folder>\cyberblue
        // v1.8: and both modes - the light versions of Hallow console and Hallow classic in <folder>\light and <folder>\classic-light
        static void SnapAll(string dir)
        {
            LoadTheme(Application.Current, HallowGuard.Look.ConsoleName, false); SnapSet(dir);
            LoadTheme(Application.Current, HallowGuard.Look.ClassicName, false); SnapSet(Path.Combine(dir, "classic"));
            LoadTheme(Application.Current, HallowGuard.Look.CyberBlueName, false); SnapSet(Path.Combine(dir, "cyberblue"));
            LoadTheme(Application.Current, HallowGuard.Look.ConsoleName, true); SnapSet(Path.Combine(dir, "light"));
            LoadTheme(Application.Current, HallowGuard.Look.ClassicName, true); SnapSet(Path.Combine(dir, "classic-light"));
            LoadTheme(Application.Current, HallowGuard.Look.CyberBlueName, true); SnapSet(Path.Combine(dir, "cyberblue-light"));   // must look the same as cyberblue
        }
        static void SnapSet(string dir)
        {
            var c = new Controller(true, true);
            var now = DateTime.Now;
            c.S.Scans = new List<ScanRecord> {
                new ScanRecord { Kind = "download", Target = @"C:\Users\Alex\Downloads\obs-studio-setup.exe", Start = now.AddHours(-3).ToString("o"), End = now.AddHours(-3).AddSeconds(4).ToString("o"), Result = "clean" },
                new ScanRecord { Kind = "quick", Start = now.AddDays(-2).AddHours(-3).ToString("o"), End = now.AddDays(-2).AddHours(-3).AddMinutes(4).ToString("o"), Result = "clean" },
                new ScanRecord { Kind = "custom", Target = @"D:\Old games", Start = now.AddDays(-80).ToString("o"), End = now.AddDays(-80).AddMinutes(9).ToString("o"), Result = "threats", Threats = 1, Note = "HackTool:Win32/Keygen" } };
            c.LoadSnapData();
            var w = new MainWindow(c);
            foreach (var page in new[] { "overview", "scan", "history", "network", "extensions", "ransomware", "hardening", "leftovers", "reports", "settings" })
            { w.Show(page); Snap.Save(w, Path.Combine(dir, page + ".png"), 1040, 720); }
            w.Show("overview"); Snap.Save(w, Path.Combine(dir, "overview-full.png"), 1040, 0);
            foreach (var page in new[] { "network", "extensions", "ransomware", "hardening" }) { w.Show(page); Snap.Save(w, Path.Combine(dir, page + "-full.png"), 1040, 0); }
            c.Names = FakeExtras.Names(); w.Show("network"); Snap.Save(w, Path.Combine(dir, "network-names.png"), 1040, 720); c.Names = new Dictionary<string, string>();
            c.SetFamily(FakeFamily.NoneInstalled()); w.Show("overview"); Snap.Save(w, Path.Combine(dir, "overview-no-apps.png"), 1040, 0);
            c.SetFamily(FakeFamily.Sample());
            c.SnapScanning(); w.Show("scan"); Snap.Save(w, Path.Combine(dir, "scan-running.png"), 1040, 720);
            w.Show("leftovers"); Snap.Save(w, Path.Combine(dir, "leftovers-full.png"), 1040, 0);
            w.Show("reports"); Snap.Save(w, Path.Combine(dir, "reports-full.png"), 1040, 0);
            c.S.AwayScan = true; c.S.AwayEvery = "daily"; c.AwayStatus = "you're using the PC"; w.Show("settings"); Snap.Save(w, Path.Combine(dir, "settings-away.png"), 1040, 0);
            c.S.AwayScan = false; c.S.AwayEvery = "weekly"; c.AwayStatus = null;
            c.SnapLookup = new VtResult { Found = true, Malicious = 9, Suspicious = 2, Undetected = 61 }.Summary; w.Show("leftovers"); Snap.Save(w, Path.Combine(dir, "leftovers-lookup.png"), 1040, 720);
            Snap.Save(CrashNotice.Make(Path.Combine(dir, "example.txt")), Path.Combine(dir, "crash.png"), 440, 0);
            // v1.4: the look picker in Settings, the scan console further on, and a PC in good shape (the pulsing ring)
            w.Show("settings"); Snap.Save(w, Path.Combine(dir, "settings-look.png"), 1040, 720);
            c.SnapScanning(); c.SnapMoreLines(); w.Show("scan"); Snap.Save(w, Path.Combine(dir, "scan-console.png"), 1040, 720);
            // v1.6: hardening before "Check (admin)" (Windows hides the exclusions), then the PC in good shape
            c.SetHardening(FakeHardening.Hidden()); w.Show("hardening"); Snap.Save(w, Path.Combine(dir, "hardening-admin.png"), 1040, 720);
            c.SetHardening(FakeHardening.Sample());
            c.SnapSecure(); w.Show("overview"); Snap.Save(w, Path.Combine(dir, "overview-secure.png"), 1040, 720);
            w.Show("hardening"); Snap.Save(w, Path.Combine(dir, "hardening-secure.png"), 1040, 0);
        }
    }

    // the app: tray icon, family pipe, the checks, scans, Watch Downloads, the weekly reminder, updates
    public class Controller
    {
        public readonly GuardSettings S = GuardSettings.Load();
        public readonly bool SnapMode;
        readonly Dispatcher ui;
        MainWindow main; WF.NotifyIcon tray; bool hubHosts, quitting, balloonOwn;
        readonly ISecurityProbe probe; readonly IThreatSource threatSource; readonly ILeftoverSource leftoverSource;
        public readonly StartupStore Store;
        readonly List<string> log = new List<string>();

        // what the pages show
        public List<Check> Checks; public SystemFacts Facts; public int ScoreValue = -1; public DateTime? CheckedAt; public bool Checking;
        // v1.1: the Hallow family - its checks, the combined score and the "Hallow apps" group score (null = no Hallow app installed)
        public List<Check> AppChecks; public FamilyFacts Fam; public int FamilyValue = -1; public int? AppsValue;
        readonly FamilyEnv famEnv; bool famReading;
        public List<ThreatRecord> ThreatList; public string ThreatError; public bool ThreatsLoading;
        public List<Leftover> LeftoverList; public bool Hunting; public string HuntStep; public DateTime? HuntedAt;
        public ScanJob Current; readonly Queue<Tuple<string, string>> queue = new Queue<Tuple<string, string>>();
        public string LastScanMessage; public List<string> WatchLog = new List<string>();
        public string SnapLookup;
        // v1.2: the network view, browser extension risk, ransomware folders, and the "Network & browsers" group of the score
        public NetSnapshot Net; public bool NetReading; public Dictionary<string, string> Names = new Dictionary<string, string>(); public bool NamesLooking;
        public List<ExtInfo> Exts; public bool ExtReading; public DateTime? ExtsAt;
        public List<Check> MoreChecks; public int? MoreValue; public List<FolderHint> Folders;
        readonly INetSource netSource; readonly IExtSource extSource;
        // v1.6: Windows hardening (read-only) - its checks and the "Hardening" group of the score
        public HardeningFacts Hard; public List<Check> HardChecks; public int? HardValue; public bool HardReading;
        readonly IHardeningSource hardSource;
        // v1.3: the quick scan while you're away, the weekly report, "what changed since last week"
        public readonly IClock Clock; readonly IIdleSource idleSrc; readonly IPowerSource powerSrc; readonly IBusySource busySrc;
        readonly AwayScanner away; public string AwayStatus;
        public List<Dictionary<string, object>> Reports = new List<Dictionary<string, object>>(); public Dictionary<string, object> LastReport;
        public SnapDiff Changes; public HashSet<string> NewIds = new HashSet<string>();
        bool reportAfterHunt, reportForce, reportNotifying, toastsFake = true;
        DownloadWatcher watcher;
        public event Action<string> Changed;   // "checks", "threats", "leftovers", "scan", "settings"

        public Controller(bool trayOnly, bool snapMode = false)
        {
            SnapMode = snapMode; ui = Dispatcher.CurrentDispatcher;
            bool fake = snapMode || GuardSettings.Fake;
            probe = fake ? (ISecurityProbe)new FakeProbe() : new WindowsProbe();
            threatSource = fake ? (IThreatSource)new FakeThreatSource() : new WindowsThreatSource();
            leftoverSource = fake ? (ILeftoverSource)new FakeLeftovers() : new WindowsLeftovers();
            netSource = fake ? (INetSource)new FakeNet() : new WindowsNet();
            extSource = fake ? (IExtSource)new FakeExts() : new WindowsExts();
            hardSource = fake ? (IHardeningSource)new FakeHardeningSource() : new WindowsHardening();
            famEnv = snapMode ? null : GuardSettings.TestDir != null ? FamilyEnv.ForTest(GuardSettings.TestDir) : FamilyEnv.Real();
            Store = GuardSettings.TestDir != null || snapMode ? StartupStore.ForTest(@"Software\HallowGuard\Test-" + (GuardSettings.TestDir == null ? "snap" : Path.GetFileName(GuardSettings.TestDir.TrimEnd('\\')))) : StartupStore.Real();
            // v1.3: real clock / idle time / power / "is a game running", or fakes (snapshots and the test copy - set over the test pipe)
            if (fake) { Clock = new FakeClock(); idleSrc = new FakeIdle(); powerSrc = new FakePower(); busySrc = new FakeBusy(); }
            else { Clock = new RealClock(); idleSrc = new WindowsIdle(); powerSrc = new WindowsPower(); busySrc = new WindowsBusy(); }
            away = new AwayScanner(Clock, idleSrc, powerSrc, busySrc)
            {
                On = () => S.AwayScan, Every = () => S.AwayEvery, LastScan = LastAnyScan, Scanning = () => Scanning, Engine = () => MpCmd.Find() != null,
                Start = () => StartScan("quick", null, true), Stop = why => { awayStopWhy = why; Log("away scan stopped: " + why); CancelScan(); }
            };
            if (snapMode) return;
            LoadReports(); LoadChanges();
            Crash.Secrets = S.GetVtKey() == null ? new string[0] : new[] { S.GetVtKey() };
            Family.Serve("Guard", Command);
            if (!GuardSettings.Headless)
            {
                SetupTray();
                var ht = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) }; ht.Tick += (s, e) => CheckHost(); ht.Start(); CheckHost();
                accentWatch = Accent.Watch(() => ui.BeginInvoke(new Action(ApplyAccent)));
                modePoll = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) }; modePoll.Tick += (s, e) => ApplyAccent(); modePoll.Start();
                if (GuardSettings.TestDir == null || Environment.GetEnvironmentVariable("HALLOW_GUARD_API") != null)
                {
                    var upd = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
                    upd.Tick += (s, e) => { upd.Interval = TimeSpan.FromHours(6); DateTime last; if (!DateTime.TryParse(S.LastUpdateCheck, out last) || (DateTime.Now - last).TotalHours >= 24) CheckForUpdate(false); };
                    upd.Start();
                }
                ui.BeginInvoke(new Action(ShowCrashNotice), DispatcherPriority.ApplicationIdle);
            }
            WriteStatus();
            RefreshChecks(); RefreshThreats();
            var st = new DispatcherTimer { Interval = TimeSpan.FromSeconds(60) }; st.Tick += (s, e) => WriteStatus(); st.Start();
            var rc = new DispatcherTimer { Interval = TimeSpan.FromHours(6) }; rc.Tick += (s, e) => { RefreshChecks(); RefreshThreats(); }; rc.Start();
            var rf = new DispatcherTimer { Interval = TimeSpan.FromMinutes(GuardSettings.TestDir != null ? 0.1 : 5) }; rf.Tick += (s, e) => RefreshFamily(); rf.Start();
            var rm = new DispatcherTimer { Interval = TimeSpan.FromMinutes(GuardSettings.TestDir != null ? 0.05 : 3) };
            rm.Tick += (s, e) => { rm.Interval = TimeSpan.FromHours(1); CheckReminder(); }; rm.Start();
            if (S.WatchDownloads) StartWatching();
            // v1.3: the away scan looks once a minute (every 5 s while its scan runs); the weekly report once an hour. Never in tests:
            // the test copy only moves when the test pipe says so (fake clock, idle time, power and game).
            if (GuardSettings.TestDir == null)
            {
                var at = new DispatcherTimer { Interval = TimeSpan.FromSeconds(60) }; at.Tick += (s, e) => { AwayTick(); at.Interval = TimeSpan.FromSeconds(away.Running ? 5 : 60); }; at.Start();
                var wr = new DispatcherTimer { Interval = TimeSpan.FromMinutes(10) }; wr.Tick += (s, e) => { wr.Interval = TimeSpan.FromHours(1); MaybeReport(false); }; wr.Start();
            }
            if (!trayOnly && !GuardSettings.Headless) ShowMain(null);
        }
        void Log(string s) { lock (log) { log.Add(DateTime.Now.ToString("HH:mm:ss") + " " + s); if (log.Count > 80) log.RemoveAt(0); } }
        void Fire(string what) { var c = Changed; if (c != null) c(what); }

        // ---- snapshots (made-up data)
        public void LoadSnapData()
        {
            Facts = probe.Read(); Checks = Score.Evaluate(Facts, LastGuardScanTime()); ScoreValue = Score.Total(Checks); CheckedAt = DateTime.Now.AddMinutes(-3);
            Net = netSource.Read(); Exts = extSource.Read(); ExtsAt = DateTime.Now.AddMinutes(-2); Hard = hardSource.Read();
            SetFamily(FakeFamily.Sample());
            string e; ThreatList = threatSource.Read(out e);
            LeftoverList = leftoverSource.Hunt(null); HuntedAt = DateTime.Now.AddMinutes(-1);
            Reports = FakeWeekly.Reports(DateTime.Now); LastReport = Reports[0]; Changes = FakeWeekly.Changes();
            NewIds = new HashSet<string>(LeftoverList.Where(l => l.Name == "SysHelper" || l.Name == "Coupon Finder Update").Select(Snapshots.IdOf));
            WatchLog = new List<string> { DateTime.Now.AddHours(-3).ToString("HH:mm") + "  obs-studio-setup.exe - nothing found", DateTime.Now.AddHours(-1).ToString("HH:mm") + "  holiday-photos.zip - nothing found" };
            S.WatchDownloads = true;
            LastScanMessage = "Quick scan finished 2 days ago - nothing found.";
        }
        public void SnapScanning()
        {
            Current = new ScanJob(null, "full", null) { Start = DateTime.Now.AddMinutes(-7).AddSeconds(-12) };
            // what MpCmdRun says (made up, like the rest)
            lock (Current.Lines) { Current.Lines.Add("Scan starting..."); Current.Times.Add(Current.Start.AddSeconds(1)); }
        }
        public void SnapMoreLines() { lock (Current.Lines) { Current.Start = DateTime.Now.AddMinutes(-41).AddSeconds(-5); Current.Times[0] = Current.Start.AddSeconds(1); } }
        // a PC in good shape (the "secure" overview)
        public void SnapSecure()
        {
            Current = null;
            foreach (var x in Checks) if (x.State == CheckState.Warn || x.State == CheckState.Bad) { x.State = CheckState.Good; x.Penalty = 0; x.FixLabel = null; }
            ScoreValue = Score.Total(Checks); Changes = null; NewIds.Clear();
            Net = FakeExtras.Network(); Net.Listeners.RemoveAll(l => l.V == Verdict.Suspicious); Net.Apps.RemoveAll(a => a.Name == "updsvc");
            Exts = FakeExtras.Extensions().Where(e => e.Risk != "High").ToList();
            SetFamily(FakeFamily.Sample()); if (AppChecks != null) foreach (var x in AppChecks) if (!x.NotInstalled && x.Penalty > 0) { x.State = CheckState.Good; x.Penalty = 0; }
            Hard = FakeHardening.Secure(); Recount();
            if (AppChecks != null) foreach (var x in AppChecks) if (!x.NotInstalled && x.Penalty > 0) { x.State = CheckState.Good; x.Penalty = 0; }
            AppsValue = FamilyScore.AppsScore(AppChecks); FamilyValue = FamilyScore.Combined(ScoreValue, AppChecks, MoreChecks, HardChecks);
        }
        public IBusySource BusySource { get { return busySrc; } }
        // v1.4: Settings > Look
        public void SetLook(string look)
        {
            S.Look = HallowGuard.Look.Normalize(look); S.Save();
            if (HallowGuard.Look.Current == S.Look) return;
            Program.LoadTheme(Application.Current, S.Look);
            if (main != null) main.Rebuild();
        }
        // v1.8: Settings > Look > Light or dark: "follow" (Hallow's switch, default) / "light" / "dark"
        public void SetMode(string mode)
        {
            S.Mode = Mode.Own(mode); S.Save();
            ApplyAccent(true);
        }

        // ---- window
        public void ShowMain(string page)
        {
            if (GuardSettings.Headless || SnapMode) return;
            if (main == null) main = new MainWindow(this);
            if (page != null) main.Show(page);
            main.Show(); if (main.WindowState == WindowState.Minimized) main.WindowState = WindowState.Normal; main.Activate();
        }
        public void MainClosed()
        {
            main = null;
            if (!S.TrayHintShown && !quitting) { S.TrayHintShown = true; S.Save(); Notify("Hallow Guard is still here", "It keeps running in the tray for Watch Downloads and reminders. Right-click the icon to quit."); }
        }
        public void Quit()
        {
            if (quitting) return; quitting = true;
            if (Current != null && !Current.Done) Current.Cancel();
            StopWatching();
            if (tray != null) { tray.Visible = false; tray.Dispose(); }
            WriteStatus(false);
            if (main != null) main.Exiting = true;
            Application.Current.Shutdown();
        }

        // ---- the safety score
        public DateTime? LastGuardScanTime()
        {
            var r = S.LastFinishedScan(); DateTime t;
            return r != null && (r.Kind == "quick" || r.Kind == "full") && DateTime.TryParse(r.End, null, System.Globalization.DateTimeStyles.RoundtripKind, out t) ? t : (DateTime?)null;
        }
        public void RefreshChecks()
        {
            if (Checking) return; Checking = true; Fire("checks");
            RefreshNetwork(); RefreshExtensions(); RefreshHardening();
            var t = new Thread(() =>
            {
                SystemFacts f = null; try { f = probe.Read(); } catch (Exception e) { Log("checks failed: " + e.Message); f = new SystemFacts(); }
                FamilyFacts ff = ReadFamily();
                ui.BeginInvoke(new Action(() =>
                {
                    Facts = f; Checks = Score.Evaluate(f, LastGuardScanTime()); ScoreValue = Score.Total(Checks); CheckedAt = DateTime.Now; Checking = false;
                    if (ff != null) Fam = ff; Recount();
                    Log("score " + ScoreValue + " family " + FamilyValue); WriteStatus(); Fire("checks");
                }));
            }) { IsBackground = true, Name = "checks" };
            t.SetApartmentState(ApartmentState.STA); t.Start();
        }
        // ---- v1.1: the Hallow family (read-only: status files, pipes, copies of browser profile files)
        FamilyFacts ReadFamily()
        {
            if (famEnv == null) return null;
            try { return FamilyProbe.Read(famEnv); } catch (Exception e) { Log("family read failed: " + e.Message); return null; }
        }
        public void RefreshFamily()
        {
            if (famReading || famEnv == null) return; famReading = true;
            new Thread(() =>
            {
                var ff = ReadFamily();
                ui.BeginInvoke(new Action(() => { famReading = false; if (ff == null) return; Fam = ff; Recount(); WriteStatus(); Fire("checks"); }));
            }) { IsBackground = true, Name = "family", Priority = ThreadPriority.BelowNormal }.Start();
        }
        public void SetFamily(FamilyFacts ff) { Fam = ff; Recount(); }
        public void SetHardening(HardeningFacts h) { Hard = h; Recount(); }
        // ---- v1.6: Windows hardening (Defender settings and exclusions, remote access, old features, accounts, Wi-Fi - read-only)
        public void RefreshHardening()
        {
            if (HardReading) return; HardReading = true; Fire("hardening");
            new Thread(() =>
            {
                HardeningFacts h; var sw = Stopwatch.StartNew();
                try { h = hardSource.Read(); } catch (Exception e) { Log("hardening failed: " + e.Message); h = null; }
                ui.BeginInvoke(new Action(() =>
                {
                    HardReading = false; if (h != null) Hard = h;
                    Log("hardening in " + sw.ElapsedMilliseconds + " ms" + (h == null ? "" : " (" + string.Join(", ", h.Timings) + ")"));   // timings only: never names, paths or Wi-Fi details
                    Recount(); WriteStatus(); Fire("hardening"); Fire("checks");
                }));
            }) { IsBackground = true, Name = "hardening", Priority = ThreadPriority.BelowNormal }.Start();
        }
        void Recount()
        {
            AppChecks = Fam == null ? null : FamilyScore.Evaluate(Fam);
            MoreChecks = Net == null && Exts == null ? null : MoreScore.Evaluate(Net, Exts);
            HardChecks = Hard == null ? null : HardScore.Evaluate(Hard, Facts);
            FamilyValue = ScoreValue < 0 ? -1 : FamilyScore.Combined(ScoreValue, AppChecks, MoreChecks, HardChecks);
            AppsValue = FamilyScore.AppsScore(AppChecks); MoreValue = MoreScore.GroupScore(MoreChecks); HardValue = HardScore.GroupScore(HardChecks);
            try
            {
                if (SnapMode || GuardSettings.Fake) Folders = FakeExtras.Hints();
                else if (Facts != null) Folders = Ransom.Suggest(Facts.Cfa, KnownFolders.Current(), Ransom.VaultSaveFolders(Fam == null || Fam.Vault == null ? null : Fam.Vault.Status), Directory.Exists);
            }
            catch (Exception e) { Log("folders: " + e.Message); }
        }
        public List<Check> AllChecks() { return (Checks ?? new List<Check>()).Concat(AppChecks ?? new List<Check>()).Concat(MoreChecks ?? new List<Check>()).Concat(HardChecks ?? new List<Check>()).ToList(); }
        // v1.3: new suspicious items since last week go first (they cost no points - they ask you to look)
        public List<Check> Todo()
        {
            var l = FamilyScore.Todo(AllChecks());
            var n = WeeklyReport.NewSuspiciousCheck(Changes);
            if (n != null) { l.Insert(0, n); if (l.Count > 5) l.RemoveAt(l.Count - 1); }
            return l;
        }

        // ---- v1.2: network view (connection tables, listeners, firewall - read-only, nothing sent out)
        public void RefreshNetwork()
        {
            if (NetReading) return; NetReading = true; Fire("network");
            new Thread(() =>
            {
                NetSnapshot n; var sw = Stopwatch.StartNew();
                try { n = netSource.Read(); } catch (Exception e) { n = new NetSnapshot { Error = e.Message }; }
                ui.BeginInvoke(new Action(() => { Net = n; NetReading = false; Log("network " + n.Apps.Count + " apps, " + n.Listeners.Count + " listeners in " + sw.ElapsedMilliseconds + " ms"); Recount(); WriteStatus(); Fire("network"); Fire("checks"); }));
            }) { IsBackground = true, Name = "network", Priority = ThreadPriority.BelowNormal }.Start();
        }
        // reverse DNS for the internet hosts on the Network page - only when you click "Look up names"
        public void LookUpNames()
        {
            if (NamesLooking || Net == null) return;
            if (GuardSettings.TestDir != null || SnapMode) { Log("look up names (tests never send anything)"); return; }
            NamesLooking = true; Fire("network");
            var ips = Net.Apps.SelectMany(a => a.Remotes).ToList();
            new Thread(() =>
            {
                Dictionary<string, string> r; try { r = WindowsNet.LookUpNames(ips); } catch { r = new Dictionary<string, string>(); }
                ui.BeginInvoke(new Action(() => { foreach (var kv in r) Names[kv.Key] = kv.Value; NamesLooking = false; Say("Looked up " + r.Count + " of " + ips.Distinct().Count() + " names."); Fire("network"); }));
            }) { IsBackground = true, Name = "names" }.Start();
        }
        // ---- v1.2: browser extension risk (manifests and copies of the browsers' settings files - never changed)
        public void RefreshExtensions()
        {
            if (ExtReading) return; ExtReading = true; Fire("extensions");
            new Thread(() =>
            {
                List<ExtInfo> l; var sw = Stopwatch.StartNew();
                try { l = extSource.Read(); } catch (Exception e) { Log("extensions failed: " + e.Message); l = new List<ExtInfo>(); }
                ui.BeginInvoke(new Action(() => { Exts = l; ExtsAt = DateTime.Now; ExtReading = false; Log("extensions " + l.Count + " in " + sw.ElapsedMilliseconds + " ms"); Recount(); WriteStatus(); Fire("extensions"); Fire("checks"); }));
            }) { IsBackground = true, Name = "extensions", Priority = ThreadPriority.BelowNormal }.Start();
        }
        public void OpenExtensionsPage(string browser)
        {
            if (GuardSettings.TestDir != null || SnapMode) { Log("extensions page " + browser + " (tests never open browsers)"); return; }
            var exe = ExtScan.BrowserExe(browser);
            if (exe == null) { Say("Couldn't find " + browser + " - open it and go to " + ExtScan.ExtensionsUrl(browser)); return; }
            try { Process.Start(exe, ExtScan.ExtensionsUrl(browser)); } catch (Exception e) { Say("Couldn't open " + browser + ": " + e.Message); }
        }
        public void RefreshThreats()
        {
            if (ThreatsLoading) return; ThreatsLoading = true;
            new Thread(() =>
            {
                string err = null; List<ThreatRecord> list = null;
                try { list = threatSource.Read(out err); } catch (Exception e) { err = e.Message; }
                ui.BeginInvoke(new Action(() => { ThreatList = list ?? new List<ThreatRecord>(); ThreatError = err; ThreatsLoading = false; WriteStatus(); Fire("threats"); }));
            }) { IsBackground = true, Name = "threats" }.Start();
        }
        // a Fix / Open settings button: opens the right Windows page. Nothing is changed by Hallow Guard itself.
        public void RunFix(string action)
        {
            if (string.IsNullOrEmpty(action)) return;
            Log("fix " + action);
            if (action == "scan:quick") { StartScan("quick", null); ShowMain("scan"); return; }
            if (action.StartsWith("page:")) { ShowMain(action.Substring(5)); return; }
            if (action == "admin:bitlocker") { CheckBitLockerAsAdmin(); return; }
            if (action == "admin:exclusions") { CheckExclusionsAsAdmin(); return; }
            if (action.StartsWith("steps:")) { var st = HardScore.Steps(action.Substring(6)); Log("steps " + action.Substring(6)); if (st != null && main != null && !SnapMode && GuardSettings.TestDir == null) main.ShowSteps(st[0], st[1]); return; }
            if (action.StartsWith("app:")) { OpenApp(action.Substring(4)); return; }
            if (GuardSettings.TestDir != null) return;   // tests never open Windows pages
            if (action.StartsWith("url:")) { var u = action.Substring(4); if (u.StartsWith("https://github.com/Dom428/")) try { Process.Start(u); } catch (Exception e) { Say("Couldn't open the page: " + e.Message); } return; }
            try
            {
                if (action == "control:bitlocker") Process.Start("control.exe", "/name Microsoft.BitLockerDriveEncryption");
                else if (action == "control:features") Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "OptionalFeatures.exe"));
                else if (action == "uac") Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "UserAccountControlSettings.exe"));
                else if (action.StartsWith("windowsdefender:") || action.StartsWith("ms-settings:")) Process.Start(action);
            }
            catch (Exception e) { Say("Couldn't open that page: " + e.Message); }
        }
        // v1.1: "Open Hallow X" (its own window: through its pipe when it runs, else start it) / "Start Hallow X" (in the tray)
        public static readonly string[] FamilyApps = { "Keys", "Vault", "Assist" };
        void OpenApp(string what)
        {
            bool start = what.StartsWith("start:"); var app = start ? what.Substring(6) : what;
            if (Array.IndexOf(FamilyApps, app) < 0) return;
            if (GuardSettings.TestDir != null) { Log("open app " + what + " (tests never start apps)"); return; }
            new Thread(() =>
            {
                string err = null;
                try
                {
                    if (!start && Family.Error(Family.Send(app, "open", 3000), "not running") == null) return;
                    var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Hallow " + app, "Hallow" + app + ".exe");
                    if (!File.Exists(exe)) err = "Hallow " + app + " isn't installed.";
                    else Process.Start(new ProcessStartInfo(exe, start ? "--tray" : "") { UseShellExecute = false });
                }
                catch (Exception e) { err = e.Message; }
                ui.BeginInvoke(new Action(() => { if (err != null) Say("Couldn't open Hallow " + app + ": " + err); else if (start) { Say("Started Hallow " + app + "."); var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(6) }; t.Tick += (s, e) => { t.Stop(); RefreshFamily(); }; t.Start(); } }));
            }) { IsBackground = true }.Start();
        }
        // reading BitLocker's status needs admin: only when you click, Windows asks (UAC), and it only reads
        void CheckBitLockerAsAdmin()
        {
            if (GuardSettings.TestDir != null) { Log("admin check skipped in tests"); return; }
            var file = WindowsProbe.BitLockerFile; Directory.CreateDirectory(Path.GetDirectoryName(file));
            var ps = "$ErrorActionPreference='Stop'; try { $s = [string](Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus } catch { $s = 'unknown' }; Set-Content -LiteralPath '" + file.Replace("'", "''") + "' -Value $s -Encoding ASCII";
            new Thread(() =>
            {
                try
                {
                    using (var p = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"" + ps.Replace("\"", "\\\"") + "\"") { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden }))
                        p.WaitForExit(60000);
                    ui.BeginInvoke(new Action(RefreshChecks));
                }
                catch { ui.BeginInvoke(new Action(() => Say("BitLocker wasn't checked (the admin prompt was closed)."))); }
            }) { IsBackground = true }.Start();
        }
        // v1.6: Defender's exclusion lists are admin-only. Only when you click: Windows asks (UAC), and it only reads them into
        // exclusions.json in Guard's data folder (trusted for 7 days) - nothing is changed.
        void CheckExclusionsAsAdmin()
        {
            if (GuardSettings.TestDir != null) { Log("admin check skipped in tests"); return; }
            var file = HardeningProbe.ExclusionsFile; Directory.CreateDirectory(Path.GetDirectoryName(file));
            var ps = "$ErrorActionPreference='Stop'; $p = Get-MpPreference; @{ paths = @($p.ExclusionPath | Where-Object { $_ }); exts = @($p.ExclusionExtension | Where-Object { $_ }); procs = @($p.ExclusionProcess | Where-Object { $_ }) } | ConvertTo-Json | Set-Content -LiteralPath '" + file.Replace("'", "''") + "' -Encoding UTF8";
            new Thread(() =>
            {
                try
                {
                    using (var p = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"" + ps.Replace("\"", "\\\"") + "\"") { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden }))
                        p.WaitForExit(60000);
                    ui.BeginInvoke(new Action(RefreshHardening));
                }
                catch { ui.BeginInvoke(new Action(() => Say("The exclusions weren't checked (the admin prompt was closed)."))); }
            }) { IsBackground = true }.Start();
        }
        public void Say(string text) { if (main != null) main.Say(text); Log(text); }

        // ---- scans (Defender's engine)
        public bool Scanning { get { return Current != null && !Current.Done; } }
        // returns null when it started (or was queued), or why not
        public string StartScan(string kind, string target, bool awayScan = false)
        {
            if (Scanning)
            {
                if (kind == "download") { lock (queue) queue.Enqueue(Tuple.Create(kind, target)); return null; }
                return "A scan is already running.";
            }
            var exe = MpCmd.Find();
            if (exe == null) return "Microsoft Defender's scanner (MpCmdRun.exe) wasn't found. Is Defender installed?";
            if ((kind == "custom" || kind == "download") && (string.IsNullOrEmpty(target) || !(File.Exists(target) || Directory.Exists(target)))) return "That file or folder isn't there.";
            var job = new ScanJob(exe, kind, target) { Away = awayScan, Low = awayScan };
            job.Finished += j => ui.BeginInvoke(new Action(() => ScanFinished(j)));
            Current = job; LastScanMessage = null; Log("scan " + kind + (target != null ? " " + target : "") + (awayScan ? " (while you're away, low priority)" : ""));
            job.Run(); WriteStatus(); Fire("scan");
            return null;
        }
        public void CancelScan() { var j = Current; if (j != null && !j.Done) new Thread(j.Cancel) { IsBackground = true }.Start(); }
        void ScanFinished(ScanJob j)
        {
            var rec = j.Record(); S.AddScan(rec); S.Save();
            var what = j.Away ? "The quick scan while you were away" : j.Kind == "quick" ? "Quick scan" : j.Kind == "full" ? "Full scan" : j.Kind == "download" ? "Download check" : "Scan of " + Path.GetFileName(j.Target.TrimEnd('\\'));
            if (j.Result == "clean") LastScanMessage = what + " finished - nothing found.";
            else if (j.Result == "threats") LastScanMessage = what + ": Defender found " + j.Threats + (j.Threats == 1 ? " threat" : " threats") + (j.Names.Count > 0 ? " (" + string.Join(", ", j.Names) + ")" : "") + ". Defender has dealt with it - see History.";
            else if (j.Result == "cancelled") LastScanMessage = j.Away ? what + " stopped (" + (awayStopWhy ?? "cancelled") + "). It tries again the next time you're away." : what + " cancelled.";
            else LastScanMessage = what + " didn't finish: " + j.Error;
            Log("scan done " + j.Kind + " " + j.Result);
            if (j.Kind == "download")
            {
                lock (WatchLog) { WatchLog.Insert(0, DateTime.Now.ToString("HH:mm") + "  " + Path.GetFileName(j.Target) + " - " + (j.Result == "clean" ? "nothing found" : j.Result == "threats" ? "THREAT FOUND" : j.Result)); if (WatchLog.Count > 12) WatchLog.RemoveAt(12); }
            }
            if (j.Result == "threats")
            {
                Notify("Hallow Guard found something", (j.Kind == "download" ? Path.GetFileName(j.Target) + ": " : what + ": ") + "Defender found " + (j.Names.Count > 0 ? j.Names[0] : "a threat") + ". Open Hallow Guard > History.");
                RefreshThreats();
            }
            else if (j.Kind != "download" && !j.Away && main == null && j.Result != "cancelled") Notify("Hallow Guard", LastScanMessage);
            if (Checks != null && Facts != null && (j.Kind == "quick" || j.Kind == "full")) { Checks = Score.Evaluate(Facts, LastGuardScanTime()); ScoreValue = Score.Total(Checks); Recount(); Fire("checks"); }
            WriteStatus(); Fire("scan");
            Tuple<string, string> next = null; lock (queue) if (queue.Count > 0) next = queue.Dequeue();
            if (next != null) StartScan(next.Item1, next.Item2);
        }

        // ---- Watch Downloads (off by default)
        public void SetWatch(bool on)
        {
            S.WatchDownloads = on; S.Save();
            if (on) StartWatching(); else StopWatching();
            WriteStatus(); Fire("scan");
        }
        void StartWatching()
        {
            StopWatching();
            try
            {
                var dir = DownloadWatcher.DownloadsFolder(); Directory.CreateDirectory(dir);
                watcher = new DownloadWatcher();
                watcher.Ready += f => ui.BeginInvoke(new Action(() => { Log("download ready " + Path.GetFileName(f)); var err = StartScan("download", f); if (err != null) Log(err); }));
                watcher.Start(dir); Log("watching " + dir);
            }
            catch (Exception e) { Log("watch failed: " + e.Message); watcher = null; }
        }
        void StopWatching() { if (watcher != null) { watcher.Dispose(); watcher = null; } }
        public bool Watching { get { return watcher != null; } }

        // ---- leftover hunt
        public void Hunt() { Hunt(false); }
        public void Hunt(bool low)
        {
            if (Hunting) return; Hunting = true; HuntStep = "Starting..."; Fire("leftovers");
            var t = new Thread(() =>
            {
                List<Leftover> list = null;
                try { list = leftoverSource.Hunt(s => ui.BeginInvoke(new Action(() => { HuntStep = s; Fire("leftovers"); }))); } catch (Exception e) { Log("hunt failed: " + e.Message); }
                ui.BeginInvoke(new Action(() =>
                {
                    LeftoverList = list ?? new List<Leftover>(); Hunting = false; HuntedAt = DateTime.Now; Log("hunt " + LeftoverList.Count);
                    if (list != null) TakeSnapshot();
                    WriteStatus(); Fire("leftovers"); Fire("checks");
                    if (reportAfterHunt) { reportAfterHunt = false; MaybeReport(reportForce); }
                }));
            }) { IsBackground = true, Name = "hunt", Priority = low ? ThreadPriority.BelowNormal : ThreadPriority.Normal };
            t.SetApartmentState(ApartmentState.STA); t.Start();
        }
        // your click on Disable / Restore (only your own Run key; machine-wide entries go to Windows' Startup apps page)
        public string DisableStartup(Leftover l)
        {
            if (l == null || l.RunValue == null) return "Only entries in your own startup list can be disabled here.";
            var err = Store.Disable(l.RunValue);
            if (err == null) { LeftoverList.Remove(l); Log("disabled " + l.RunValue); }
            Fire("leftovers"); return err;
        }
        public string RestoreStartup(string id) { var err = Store.Restore(id); Log("restore " + id + " " + (err ?? "ok")); Fire("leftovers"); return err; }

        // ---- v1.3: "what changed since last week" (a small snapshot after each look: hashed IDs and short names, no file contents)
        string SnapFile(string week) { return Path.Combine(Snapshots.Dir(GuardSettings.Dir), week + ".json"); }
        void TakeSnapshot()
        {
            if (SnapMode || LeftoverList == null) return;
            try
            {
                List<string> kinds; var items = Snapshots.Take(LeftoverList, Net, out kinds);
                var week = Weeks.Key(Clock.Now);
                Snapshots.Save(GuardSettings.Dir, week, items, kinds, Clock.Now);
                SetChanges(CompareWithBefore(week, items, kinds));
                Log("snapshot " + week + ": " + items.Count + " items" + (Changes == null ? " (the first one)" : ", " + Changes.New.Count + " new, " + Changes.Removed.Count + " removed since " + Changes.Since));
            }
            catch (Exception e) { Log("snapshot failed: " + e.Message); }
        }
        SnapDiff CompareWithBefore(string week, List<SnapItem> items, List<string> kinds)
        {
            var b = Snapshots.Before(GuardSettings.Dir, week); if (b == null) return null;
            List<SnapItem> bi; List<string> bk;
            return Snapshots.Load(SnapFile(b), out bi, out bk) ? Snapshots.Compare(bi, bk, items, kinds, b) : null;
        }
        void SetChanges(SnapDiff d) { Changes = d; NewIds = new HashSet<string>(d == null ? new string[0] : d.New.Select(x => x.Id)); }
        void LoadChanges()
        {
            try { var week = Weeks.Key(Clock.Now); List<SnapItem> i; List<string> k; if (Snapshots.Load(SnapFile(week), out i, out k)) SetChanges(CompareWithBefore(week, i, k)); }
            catch (Exception e) { Log("changes: " + e.Message); }
        }

        // ---- v1.3: the quick scan while you're away (off by default; needs Hallow Guard running in the tray)
        string awayStopWhy;
        public string AwayTick()
        {
            if (SnapMode) return "wait";
            if (!S.AwayScan && !away.Running) { AwayStatus = "it's off"; return "wait"; }
            string r; try { r = away.Tick(); } catch (Exception e) { r = "error"; away.Status = e.Message; }
            AwayStatus = away.Status;
            if (r != "wait" && r != "running") { Log("away scan: " + r + " - " + away.Status); WriteStatus(); Fire("settings"); }
            return r;
        }
        public void SetAway(bool on, string every)
        {
            S.AwayScan = on; if (every != null) S.AwayEvery = every == "daily" ? "daily" : "weekly"; S.Save();
            if (!on && away.Running) { away.Running = false; awayStopWhy = "you switched it off"; CancelScan(); }
            AwayStatus = on ? "waiting until you're away" : "it's off"; WriteStatus(); Fire("settings");
        }
        public DateTime? LastAwayScan() { lock (S.Scans) foreach (var s in S.Scans) if (s.Away && (s.Result == "clean" || s.Result == "threats")) { DateTime t; if (DateTime.TryParse(s.End, null, System.Globalization.DateTimeStyles.RoundtripKind, out t)) return t; } return null; }

        // ---- v1.3: the weekly safety report (reports\<yyyy-ww>.json + .txt), once a week while Hallow Guard runs
        public void LoadReports() { try { Reports = WeeklyReport.List(GuardSettings.Dir); LastReport = Reports.FirstOrDefault(); } catch (Exception e) { Log("reports: " + e.Message); } }
        // force = "Make it now" (or the test pipe): doesn't wait for a game to end
        public void MaybeReport(bool force)
        {
            if (SnapMode) return;
            var now = Clock.Now; var week = Weeks.Key(now);
            if (!force && S.LastReportWeek == week) { NotifyReport(); return; }
            if (Checks == null || Checking || ThreatsLoading || ScoreValue < 0) { Log("report: waiting for the checks"); return; }
            var busy = busySrc.Busy(); if (busy != null && !force) { Log("report: waiting - " + busy); return; }
            // a fresh look at the leftovers first (in the background, low priority), so the report can say what changed
            if (LeftoverList == null || HuntedAt == null || (DateTime.Now - HuntedAt.Value).TotalHours > 12)
            {
                reportAfterHunt = true; reportForce = force;
                if (!Hunting) Hunt(true);
                return;
            }
            try
            {
                List<ScanRecord> scans; lock (S.Scans) scans = S.Scans.ToList();
                var r = WeeklyReport.Build(new ReportInput
                {
                    Now = now, Week = week, Score = FamilyValue >= 0 ? FamilyValue : ScoreValue, Checks = AllChecks(), Scans = scans,
                    DefenderQuick = Facts == null ? null : Facts.QuickScan, DefenderFull = Facts == null ? null : Facts.FullScan,
                    Threats = ThreatError == null ? ThreatList : null, Changes = Changes, Previous = WeeklyReport.Before(GuardSettings.Dir, week)
                });
                WeeklyReport.Save(GuardSettings.Dir, r);
                S.LastReportWeek = week; S.Save();
                LoadReports(); Log("report " + week + ": " + J.Str(r, "summary"));
                WriteStatus(); Fire("reports");
                NotifyReport();
            }
            catch (Exception e) { Log("report failed: " + e.Message); }
        }
        public int ReportBalloons;
        // one balloon a week, only through Hallow Hub (when it runs with its icon showing) and only with notifications on
        void NotifyReport()
        {
            var r = LastReport; if (r == null || reportNotifying || SnapMode) return;
            var week = J.Str(r, "week");
            if (week != Weeks.Key(Clock.Now) || !S.ReportNotify || week == S.LastReportNotified) return;
            var busy = busySrc.Busy(); var toasts = GuardSettings.Fake ? toastsFake : WeeklyReport.WindowsToastsOn();
            var title = WeeklyReport.Headline(r); var text = J.Str(r, "summary") + " Open Hallow Guard > Reports.";
            var last = S.LastReportNotified; reportNotifying = true;
            ThreadPool.QueueUserWorkItem(_ =>
            {
                bool on = false, lists, sent = false;
                try { var h = Family.Send("Hub", "tray-host", 1500); if (h != null && h.StartsWith("ok {")) HubHosting(h.Substring(3), out on, out lists); } catch { }
                if (WeeklyReport.ShouldNotify(true, toasts, on, busy, week, last))
                    sent = Family.Error(Family.Send("Hub", "notify Guard\t" + title + "\t" + text, 2000), "no answer") == null;
                ui.BeginInvoke(new Action(() =>
                {
                    reportNotifying = false;
                    if (sent) { S.LastReportNotified = week; S.Save(); ReportBalloons++; }
                    Log("report balloon: " + (sent ? "sent through Hub" : "not sent (Hub icon " + (on ? "on" : "off") + ", notifications " + (toasts ? "on" : "off") + (busy != null ? ", " + busy : "") + ")"));
                }));
            });
        }
        string ReportCommand(string arg)
        {
            if (arg == "list") return "ok " + Family.Json(new Dictionary<string, object> { { "weeks", WeeklyReport.WeeksIn(GuardSettings.Dir) } });
            if (arg.Length > 0 && !Weeks.Valid(arg)) return "error usage: report [yyyy-ww|list]";
            var r = arg.Length == 0 ? LastReport : WeeklyReport.Load(GuardSettings.Dir, arg);
            return r == null ? "error no report " + (arg.Length == 0 ? "yet" : "for " + arg) : "ok " + Family.Json(r);
        }

        // ---- VirusTotal (hash only)
        public void LookUp(string file, Action<string> done)
        {
            new Thread(() =>
            {
                string msg;
                try
                {
                    var hash = VtClient.Sha256File(file); var key = S.GetVtKey();
                    if (key == null)
                    {
                        if (GuardSettings.TestDir == null) Process.Start(VtClient.GuiUrl(hash));
                        msg = "Opened VirusTotal in your browser (only the file's fingerprint is in the address - the file isn't uploaded).";
                    }
                    else
                    {
                        var api = GuardSettings.TestDir != null ? Environment.GetEnvironmentVariable("HALLOW_GUARD_VT") : null;
                        msg = new VtClient(key, api).Lookup(hash).Summary;
                    }
                }
                catch (Exception e) { msg = "Couldn't look it up: " + e.Message; }
                ui.BeginInvoke(new Action(() => done(msg)));
            }) { IsBackground = true }.Start();
        }
        public static void OpenLocation(string file)
        {
            if (string.IsNullOrEmpty(file) || GuardSettings.TestDir != null) return;
            try
            {
                if (File.Exists(file)) Process.Start("explorer.exe", "/select,\"" + file + "\"");
                else if (Directory.Exists(file)) Process.Start("explorer.exe", "\"" + file + "\"");
                else { var d = Path.GetDirectoryName(file); if (Directory.Exists(d)) Process.Start("explorer.exe", "\"" + d + "\""); }
            }
            catch { }
        }

        // ---- Start with Windows (its own Run entry, off unless you switch it on; tests never touch the real Run key)
        string RunFile { get { return Path.Combine(GuardSettings.Dir, "run-key-test.txt"); } }
        public bool StartsWithWindows()
        {
            if (GuardSettings.TestDir != null || SnapMode) return File.Exists(RunFile);
            try { using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(WindowsLeftovers.UserRun)) return k != null && k.GetValue("HallowGuard") != null; } catch { return false; }
        }
        public void SetStartWithWindows(bool on)
        {
            if (SnapMode) return;
            if (GuardSettings.TestDir != null) { if (on) File.WriteAllText(RunFile, "\"HallowGuard.exe\" --tray"); else if (File.Exists(RunFile)) File.Delete(RunFile); return; }
            try { using (var k = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(WindowsLeftovers.UserRun)) { if (on) k.SetValue("HallowGuard", "\"" + Assembly.GetExecutingAssembly().Location + "\" --tray"); else k.DeleteValue("HallowGuard", false); } } catch { }
        }
        // ---- weekly reminder: a balloon (never a scan) when nothing was scanned for 7 days
        public DateTime? LastAnyScan()
        {
            DateTime? best = LastGuardScanTime();
            if (Facts != null) foreach (var t in new[] { Facts.QuickScan, Facts.FullScan }) if (t != null && (best == null || t > best)) best = t;
            return best;
        }
        public static bool ReminderDue(DateTime? lastScan, DateTime? lastReminder, DateTime now)
        {
            if (lastScan != null && (now - lastScan.Value).TotalDays < 7) return false;
            return lastReminder == null || (now - lastReminder.Value).TotalDays >= 7;
        }
        void CheckReminder()
        {
            if (!S.WeeklyReminder || Facts == null || (Facts.OtherAv != null && Facts.OtherAv.Count > 0)) return;
            DateTime lr; var last = DateTime.TryParse(S.LastReminder, null, System.Globalization.DateTimeStyles.RoundtripKind, out lr) ? lr : (DateTime?)null;
            if (!ReminderDue(LastAnyScan(), last, DateTime.Now)) return;
            S.LastReminder = DateTime.Now.ToString("o"); S.Save();
            Log("weekly reminder");
            Notify("Time for a quick scan", "Nothing was scanned for a week. Open Hallow Guard and click Quick scan - it takes a few minutes.");
        }

        // ---- tray, the Hallow icon (Hub hosts it), notifications, accent, updates, crash notice
        void SetupTray()
        {
            tray = new WF.NotifyIcon { Text = "Hallow Guard", Visible = true };
            try { tray.Icon = System.Drawing.Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location); } catch { tray.Icon = System.Drawing.SystemIcons.Application; }
            var menu = new WF.ContextMenuStrip();
            var open = new WF.ToolStripMenuItem("Open Hallow Guard"); open.Font = new System.Drawing.Font(open.Font, System.Drawing.FontStyle.Bold); open.Click += (s, e) => ShowMain(null); menu.Items.Add(open);
            var quick = new WF.ToolStripMenuItem("Quick scan"); quick.Click += (s, e) => Invoke("quick"); menu.Items.Add(quick);
            var watch = new WF.ToolStripMenuItem("Watch Downloads"); watch.Click += (s, e) => Invoke("watch"); menu.Items.Add(watch);
            menu.Opening += (s, e) => { quick.Enabled = !Scanning; watch.Checked = S.WatchDownloads; };
            menu.Items.Add(new WF.ToolStripSeparator());
            var quit = new WF.ToolStripMenuItem("Quit"); quit.Click += (s, e) => Quit(); menu.Items.Add(quit);
            tray.ContextMenuStrip = menu;
            tray.MouseClick += (s, e) => { if (e.Button == WF.MouseButtons.Left) ShowMain(null); };
            StyleTrayMenu();
        }
        // v1.8: the tray menu in the app's colours - light or dark (Cyber blue: dark)
        void StyleTrayMenu()
        {
            if (tray == null || tray.ContextMenuStrip == null) return;
            var m = tray.ContextMenuStrip; var p = TrayColors.For(Mode.IsLight);
            m.Renderer = new WF.ToolStripProfessionalRenderer(p) { RoundedEdges = false };
            m.BackColor = p.Back; m.ForeColor = p.Fore;
            foreach (WF.ToolStripItem it in m.Items) { it.BackColor = p.Back; it.ForeColor = p.Fore; }
        }
        public void CheckHost()
        {
            if (tray == null) return;
            if (!S.UseHallowIcon) { SetHosted(false, false); return; }
            ThreadPool.QueueUserWorkItem(_ =>
            {
                bool on = false, lists = false;
                try { var r = Family.Send("Hub", "tray-host", 1500); if (r != null && r.StartsWith("ok {")) HubHosting(r.Substring(3), out on, out lists); } catch { }
                ui.BeginInvoke(new Action(() => SetHosted(on && S.UseHallowIcon, lists)));
            });
        }
        // Hub's "tray-host" answer: on = Hub's Hallow icon is showing (balloons go through it); lists = Hub's menu has a Hallow Guard
        // entry ("apps" contains "Guard" or "generic":true). Guard only hides its own icon when Hub lists it, so it's never unreachable.
        public static void HubHosting(string json, out bool on, out bool lists)
        {
            on = false; lists = false;
            try
            {
                var d = new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json); object v;
                on = d != null && d.TryGetValue("on", out v) && v is bool && (bool)v;
                if (!on) return;
                if (d.TryGetValue("generic", out v) && v is bool && (bool)v) { lists = true; return; }
                if (d.TryGetValue("apps", out v) && v is System.Collections.IEnumerable && !(v is string))
                    foreach (var a in (System.Collections.IEnumerable)v) if (a is string && string.Equals((string)a, "Guard", StringComparison.OrdinalIgnoreCase)) lists = true;
            }
            catch { on = false; lists = false; }
        }
        bool hubLists;
        void SetHosted(bool on, bool lists) { hubHosts = on; hubLists = on && lists; if (tray != null && !balloonOwn) tray.Visible = !hubLists; }
        public int Notifications;
        public void Notify(string title, string text)
        {
            Notifications++; Log("notify: " + title + " - " + text);
            if (tray == null || GuardSettings.TestDir != null) return;
            if (!hubHosts) { tray.ShowBalloonTip(5000, title, text, WF.ToolTipIcon.None); return; }
            ThreadPool.QueueUserWorkItem(_ =>
            {
                if (Family.Error(Family.Send("Hub", "notify Guard\t" + title + "\t" + text, 2000), "no answer") == null) return;
                ui.BeginInvoke(new Action(() => { balloonOwn = true; tray.Visible = true; tray.ShowBalloonTip(5000, title, text, WF.ToolTipIcon.None); var t = new DispatcherTimer { Interval = TimeSpan.FromSeconds(7) }; t.Tick += (s, e) => { t.Stop(); balloonOwn = false; SetHosted(hubHosts, hubLists); }; t.Start(); }));
            });
        }
        FileSystemWatcher accentWatch;
        // theme.json changed (accent or v1.8's mode), Windows' app mode changed (the poll), or a setting: re-theme only if something differs
        public void ApplyAccent() { ApplyAccent(false); }
        public void ApplyAccent(bool force)
        {
            var a = Accent.Current(S.UseHallowAccent);
            var light = Mode.Resolve(S.Look, S.Mode, Accent.ReadMode(), Mode.Sys);
            if (!force && a == Program.AccentHex && light == Mode.IsLight) return;
            Program.LoadTheme(Application.Current, S.Look);
            if (main != null) main.Rebuild();
            StyleTrayMenu();
            Log("theme: accent " + Program.AccentHex + ", " + (Mode.IsLight ? "light" : "dark"));
        }
        // the poll for "Same as Windows" (and a theme.json made after start, which the folder watcher can't see): cheap - one
        // registry value and one small file, every 4 s, only re-themes when the answer changes
        DispatcherTimer modePoll;
        GhRelease pending; public GhRelease PendingUpdate { get { return pending; } }
        public void CheckForUpdate(bool manual)
        {
            if (manual) Say("Checking GitHub for a newer Hallow Guard...");
            new Thread(() =>
            {
                var r = Updater.Latest();
                ui.BeginInvoke(new Action(() =>
                {
                    S.LastUpdateCheck = DateTime.Now.ToString("o"); S.Save();
                    if (r == null) { if (manual) Say("Couldn't reach GitHub - try again later."); return; }
                    if (!Updater.IsNewer(r)) { if (manual) Say("You have the newest version (v" + Program.Version + ")."); return; }
                    pending = r; if (main != null) main.ShowUpdate("Update to v" + r.Version.ToString(2));
                    Say("Hallow Guard v" + r.Version.ToString(2) + " is out - click Update at the top.");
                }));
            }) { IsBackground = true }.Start();
        }
        public void InstallUpdate()
        {
            if (pending == null) return;
            if (Scanning) { MessageBox.Show(main, "Wait for the scan to finish - updating restarts Hallow Guard.", "Hallow Guard"); return; }
            if (MessageBox.Show(main, "Install Hallow Guard v" + pending.Version.ToString(2) + " now?\n\nIt downloads from GitHub, checks the file and puts the new version in place. Your settings stay.", "Update Hallow Guard", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
            var r = pending; Say("Updating...");
            new Thread(() => { var err = Updater.Install(r); ui.BeginInvoke(new Action(() => Say(err ?? "Installing the update..."))); }) { IsBackground = true }.Start();
        }
        void ShowCrashNotice()
        {
            var f = Crash.Last(); if (f == null) return;
            var name = Path.GetFileName(f); if (name == S.LastCrashShown) return;
            S.LastCrashShown = name; S.Save();
            CrashNotice.Make(f).Show();
        }

        // ---- family link: status.json and the pipe
        public Dictionary<string, object> StatusData(bool running = true)
        {
            var last = S.LastFinishedScan(); DateTime? any = LastAnyScan();
            var d = new Dictionary<string, object> {
                { "app", "Guard" }, { "version", Program.Version }, { "updated", Family.Time(DateTime.Now) }, { "running", running },
                { "score", ScoreValue >= 0 ? (object)ScoreValue : null }, { "scoreLabel", ScoreValue >= 0 ? Score.Label(ScoreValue) : null },
                { "familyScore", FamilyValue >= 0 ? (object)FamilyValue : null }, { "familyLabel", FamilyValue >= 0 ? Score.Label(FamilyValue) : null },
                { "windowsScore", ScoreValue >= 0 ? (object)ScoreValue : null }, { "appsScore", AppsValue },
                { "todo", Checks == null ? null : (object)Todo().Count }, { "family", FamilyStates() },
                { "checked", CheckedAt == null ? null : Family.Time(CheckedAt.Value) },
                { "lastScan", any == null ? null : Family.Time(any.Value) },
                { "lastGuardScan", last == null ? null : last.End }, { "lastGuardScanKind", last == null ? null : last.Kind }, { "lastGuardScanResult", last == null ? null : last.Result },
                { "scanning", Scanning }, { "scanKind", Scanning ? Current.Kind : null },
                { "threats", ThreatList == null || ThreatError != null ? null : (object)ThreatList.Count },
                { "watchDownloads", S.WatchDownloads }, { "weeklyReminder", S.WeeklyReminder }, { "startsWithWindows", StartsWithWindows() }, { "virusTotalKey", S.VtKey != null },
                { "lastCrash", Crash.LastTime() == null ? null : Family.Time(Crash.LastTime().Value) },
                // v1.2: ransomware protection, programs open to the network, browser extensions (counts only - no names, addresses or paths)
                { "ransomware", Facts == null || Facts.Cfa == null ? null : Ransom.ModeWord(Facts.Cfa.Mode) }, { "moreScore", MoreValue }, { "hardeningScore", HardValue },
                { "network", Net == null || Net.Error != null ? null : new Dictionary<string, object> { { "apps", Net.Apps.Count }, { "listeners", Net.Listeners.Count }, { "suspicious", Net.Listeners.Count(l => l.V == Verdict.Suspicious) } } },
                { "extensions", Exts == null ? null : new Dictionary<string, object> { { "total", Exts.Count }, { "high", Exts.Count(x => x.Risk == "High") }, { "medium", Exts.Count(x => x.Risk == "Medium") }, { "low", Exts.Count(x => x.Risk == "Low") }, { "known", Exts.Count(x => x.Known) } } },
                // v1.3: the away scan, the newest weekly report (counts only) and what changed since last week (counts only)
                { "awayScan", S.AwayScan }, { "awayEvery", S.AwayEvery }, { "lastAwayScan", LastAwayScan() == null ? null : Family.Time(LastAwayScan().Value) },
                { "lastReport", WeeklyReport.Brief(LastReport) },
                { "changes", Changes == null ? null : new Dictionary<string, object> { { "since", Changes.Since }, { "new", Changes.New.Count }, { "removed", Changes.Removed.Count }, { "newSuspicious", Changes.NewSuspicious } } } };
            if (GuardSettings.TestDir != null) d["test"] = TestState();
            return d;
        }
        // v1.1: each Hallow app' state for other apps: good / warn / bad / unknown / info, or "missing" (not installed)
        Dictionary<string, object> FamilyStates()
        {
            if (AppChecks == null) return null;
            var d = new Dictionary<string, object>();
            foreach (var x in AppChecks) d[x.Id] = x.NotInstalled ? "missing" : x.State.ToString().ToLowerInvariant();
            return d;
        }
        public void WriteStatus(bool running = true) { if (!SnapMode) Family.WriteStatus(Family.Json(StatusData(running))); }
        Dictionary<string, object> TestState()
        {
            var t = new Dictionary<string, object> { { "watching", Watching }, { "notifications", Notifications }, { "queue", queue.Count }, { "hunting", Hunting },
                { "leftovers", LeftoverList == null ? -1 : LeftoverList.Count }, { "lastMessage", LastScanMessage } };
            if (Checks != null) t["checks"] = Checks.Select(x => x.Id + "=" + x.State + (x.Penalty > 0 ? " -" + x.Penalty : "")).ToArray();
            if (HardChecks != null) t["hardChecks"] = HardChecks.Select(x => x.Id + "=" + x.State + (x.Penalty > 0 ? " -" + x.Penalty : "")).ToArray();
            if (MoreChecks != null) t["moreChecks"] = MoreChecks.Select(x => x.Id + "=" + x.State + (x.Penalty > 0 ? " -" + x.Penalty : "")).ToArray();
            if (AppChecks != null) t["appChecks"] =AppChecks.Select(x => x.Id + "=" + (x.NotInstalled ? "missing" : x.State.ToString()) + (x.Penalty > 0 ? " -" + x.Penalty : "")).ToArray();
            if (Checks != null) t["todoIds"] = Todo().Select(x => x.Id).ToArray();
            if (LeftoverList != null) t["verdicts"] = LeftoverList.GroupBy(x => x.Kind + "/" + x.V).Select(g => g.Key + ":" + g.Count()).ToArray();
            t["away"] = away.Status; t["awayRunning"] = away.Running; t["reportBalloons"] = ReportBalloons; t["newIds"] = NewIds.Count;
            if (Current != null) { t["jobAway"] = Current.Away; }
            if (Current != null) { t["job"] = Current.Kind; t["jobResult"] = Current.Result; t["jobThreats"] = Current.Threats; t["jobTarget"] = Current.Target; }
            lock (log) t["log"] = log.ToArray();
            return t;
        }
        string Command(string line)
        {
            int sp = line.IndexOf(' '); var cmd = sp < 0 ? line : line.Substring(0, sp); var arg = sp < 0 ? "" : line.Substring(sp + 1).Trim();
            switch (cmd)
            {
                case "ping": return "ok " + Family.Json(new Dictionary<string, object> { { "app", "Guard" }, { "version", Program.Version } });
                case "status": return OnUi(() => { var d = StatusData(); Family.WriteStatus(Family.Json(d)); return "ok " + Family.Json(d); });
                case "open": return OnUi(() => { ShowMain(arg.Length > 0 ? arg : null); return "ok"; });
                case "menu": return OnUi(() => "ok " + Family.Json(new Dictionary<string, object> { { "app", "Guard" }, { "items", MenuItems() } }));
                case "invoke": return OnUi(() => Invoke(arg));
                case "scan":
                    if (arg != "quick") return "error only \"scan quick\" can be started from outside";
                    return OnUi(() => { var e = StartScan("quick", null); return e == null ? "ok" : "error " + e; });
                case "report": return OnUi(() => ReportCommand(arg));
                case "quit": new Thread(() => { Thread.Sleep(300); ui.BeginInvoke(new Action(Quit)); }) { IsBackground = true }.Start(); return "ok";
            }
            if (GuardSettings.TestDir != null && cmd.StartsWith("test-")) return OnUi(() => TestCommand(cmd, arg));
            return "error unknown command";
        }
        string OnUi(Func<string> f)
        {
            string r = "error no answer in time";
            var op = ui.BeginInvoke(new Action(() => { try { r = f(); } catch (Exception e) { r = "error " + Family.OneLine(e.Message); } }));
            return op.Wait(TimeSpan.FromSeconds(5)) == DispatcherOperationStatus.Completed ? r : "error no answer in time";
        }
        List<object> MenuItems()
        {
            return new List<object> {
                new Dictionary<string, object> { { "id", "quick" }, { "label", "Quick scan" }, { "enabled", !Scanning } },
                new Dictionary<string, object> { { "id", "check" }, { "label", "Check my PC" } },
                new Dictionary<string, object> { { "id", "-" } },
                new Dictionary<string, object> { { "id", "watch" }, { "label", "Watch Downloads" }, { "checked", S.WatchDownloads } } };
        }
        string Invoke(string id)
        {
            switch (id)
            {
                case "quick": { var e = StartScan("quick", null); return e == null ? "ok" : "error " + e; }
                case "check": RefreshChecks(); ShowMain("overview"); return "ok";
                case "watch": SetWatch(!S.WatchDownloads); return "ok";
            }
            return "error unknown item";
        }
        // developer tests only (HALLOW_GUARD_TESTDIR): what a person would click, without windows
        string TestCommand(string cmd, string arg)
        {
            switch (cmd)
            {
                case "test-scan-file": { var e = StartScan("custom", arg); return e == null ? "ok" : "error " + e; }
                case "test-scan-full": { var e = StartScan("full", null); return e == null ? "ok" : "error " + e; }
                case "test-cancel": CancelScan(); return "ok";
                case "test-watch": SetWatch(arg == "on"); return "ok";
                case "test-hunt": Hunt(); return "ok";
                case "test-checks": RefreshChecks(); return "ok";
                case "test-family": RefreshFamily(); return "ok";
                case "test-network": RefreshNetwork(); return "ok";
                case "test-extensions": RefreshExtensions(); return "ok";
                case "test-names": LookUpNames(); return "ok";
                case "test-extpage": OpenExtensionsPage(arg); return "ok";
                case "test-reminder": S.LastReminder = null; S.Save(); CheckReminder(); return "ok " + Notifications;
                case "test-fix": RunFix(arg); return "ok";
                case "test-autostart": SetStartWithWindows(arg == "on"); return "ok";
                case "test-vtkey": S.SetVtKey(arg); S.Save(); return "ok";
            }
            // v1.3: the fake clock, idle time, power, game and notifications of the test copy
            if (!GuardSettings.Fake) return "error unknown test command";
            switch (cmd)
            {
                case "test-idle": ((FakeIdle)idleSrc).Value = TimeSpan.FromSeconds(double.Parse(arg, System.Globalization.CultureInfo.InvariantCulture)); return "ok";
                case "test-power": ((FakePower)powerSrc).Value = arg == "ac" ? true : arg == "battery" ? false : (bool?)null; return "ok";
                case "test-busy": ((FakeBusy)busySrc).Value = arg == "off" || arg.Length == 0 ? null : arg; return "ok";
                case "test-clock": { var fc = (FakeClock)Clock; if (arg == "now") fc.Offset = TimeSpan.Zero; else fc.Offset = DateTime.Parse(arg, null, System.Globalization.DateTimeStyles.RoundtripKind) - DateTime.Now; return "ok"; }
                case "test-away": { var p = arg.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries); SetAway(p.Length > 0 && p[0] == "on", p.Length > 1 ? p[1] : null); return "ok"; }
                case "test-away-tick": { var r = AwayTick(); return "ok " + r + " - " + away.Status; }
                case "test-report": MaybeReport(true); return "ok";
                case "test-toasts": toastsFake = arg != "off"; return "ok";
                case "test-reload": LoadChanges(); LoadReports(); WriteStatus(); return "ok";
            }
            return "error unknown test command";
        }
    }
}
