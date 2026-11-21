// Hallow Guard 1.2 unit tests, all with made-up data in a temp folder: a fake Controlled folder access state and save folders,
// fake TCP/UDP table rows (the raw bytes Windows returns), listeners grouped and rated with a fake firewall, and fake Chrome /
// Edge / Brave / Opera / Firefox profile folders with manifests and Preferences (locked and broken files too, and the browser
// files never changed). No real setting, connection or browser is read here - except "--real-timing", which only times the
// real read-only checks and prints counts.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace HallowGuard.Tests
{
    public static class V12Tests
    {
        static Action<bool, string> Ok;
        static string Root;

        public static void All(Action<bool, string> ok)
        {
            Ok = ok;
            Root = Path.Combine(Path.GetTempPath(), "HallowGuardV12Test" + Process.GetCurrentProcess().Id);
            try
            {
                if (Directory.Exists(Root)) Directory.Delete(Root, true); Directory.CreateDirectory(Root);
                Cfa(); Tables(); Listeners(); Firewall(); Extensions(); Firefox(); Numbers();
            }
            finally { try { Directory.Delete(Root, true); } catch { } }
        }

        // ---------------- ransomware protection
        static void Cfa()
        {
            var c = Ransom.FromPreference((byte)1, new[] { @"D:\Photos", @"D:\Photos" }, new[] { @"C:\Games\game.exe" });
            Ok(c.Read && c.Mode == 1 && c.Protected.Count == 1 && c.Allowed.Count == 1 && !c.ListsHidden, "CFA from MSFT_MpPreference: on, one folder (no duplicates), one app");
            c = Ransom.FromPreference((byte)0, new[] { "N/A: Must be an administrator to view exclusions" }, null);
            Ok(c.Mode == 0 && c.Protected.Count == 0 && c.ListsHidden, "CFA lists Windows hides from non-admins: 'hidden', not a folder");
            Ok(Ransom.FromPreference(null, null, null).Mode == null, "CFA value missing: unknown");
            var ch = Ransom.Evaluate(new CfaFacts { Read = true, Mode = 0 }, null);
            Ok(ch.Id == "cfa" && ch.State == CheckState.Warn && ch.Penalty == 3 && ch.Line.Contains("block some games"), "CFA off: warn, 3 points (light), mentions games");
            Ok(Ransom.Evaluate(new CfaFacts { Read = true, Mode = 1 }, null).State == CheckState.Good && Ransom.Evaluate(new CfaFacts { Read = true, Mode = 1 }, null).Penalty == 0, "CFA on: good");
            Ok(Ransom.Evaluate(new CfaFacts { Read = true, Mode = 2 }, null).Penalty == 2 && Ransom.Evaluate(new CfaFacts { Read = true, Mode = 3 }, null).Penalty == 2, "CFA audit / disk-only: 2 points");
            Ok(Ransom.Evaluate(null, null).State == CheckState.Unknown && Ransom.Evaluate(null, null).Penalty == 0, "CFA unreadable: unknown, no points");
            var o = Ransom.Evaluate(new CfaFacts { Read = true, Mode = 0 }, new List<string> { "Some Antivirus" });
            Ok(o.State == CheckState.Info && o.Penalty == 0 && o.FixAction == null, "another antivirus: CFA isn't Defender's job, no points");
            Ok(new[] { 0, 1, 2, 3 }.Select(m => Ransom.Evaluate(new CfaFacts { Read = true, Mode = m }, null).FixAction).All(a => a == "page:ransomware"), "CFA button opens Guard's Ransomware page");
            Ok(Ransom.Page == "windowsdefender://ransomwareprotection/", "the Ransomware page's buttons open windowsdefender://ransomwareprotection/ only");
            // Vault's save folders (status.json) and the suggestions
            var vs = J.Parse("{\"games\":[{\"name\":\"A\",\"saveDirs\":[\"E:\\\\Saves\\\\A\",\"C:\\\\Users\\\\Alex\\\\Documents\\\\My Games\\\\A\"]},{\"name\":\"B\",\"off\":true,\"saveDirs\":[\"E:\\\\Saves\\\\B\"]},{\"name\":\"C\",\"saves\":\"E:\\\\Saves\\\\C\\\\\"},{\"name\":\"D\",\"installDir\":\"G:\\\\Steam\\\\D\"}],\"saveFolders\":[\"F:\\\\More\"]}");
            var vf = Ransom.VaultSaveFolders(vs);
            Ok(vf.Count == 4 && vf.Contains(@"E:\Saves\A") && vf.Contains(@"E:\Saves\C") && vf.Contains(@"F:\More") && !vf.Contains(@"E:\Saves\B") && !vf.Any(x => x.StartsWith("G:")), "Vault save folders: per game + top level, switched-off games and install folders skipped");
            Ok(Ransom.VaultSaveFolders(J.Parse("{\"games\":[{\"name\":\"X\",\"installDir\":\"G:\\\\X\"}]}")).Count == 0 && Ransom.VaultSaveFolders(null).Count == 0, "Vault 1.12 (no save folders in status.json) or no Vault: nothing");
            var k = new KnownFolders { Documents = @"C:\Users\Alex\Documents", Pictures = @"C:\Users\Alex\Pictures", Desktop = @"C:\Users\Alex\Desktop", SavedGames = @"C:\Users\Alex\Saved Games" };
            var off = Ransom.Suggest(new CfaFacts { Read = true, Mode = 0 }, k, vf, p => !p.StartsWith("F:"));
            Func<List<FolderHint>, string, FolderHint> at = (l, p) => l.FirstOrDefault(h => h.Path.Equals(p, StringComparison.OrdinalIgnoreCase));
            Ok(new[] { k.Documents, k.Pictures, k.Desktop }.All(p => at(off, p) != null && at(off, p).Status == "default"), "CFA off: Documents, Pictures, Desktop protected as soon as it's on");
            Ok(at(off, k.SavedGames).Status == "suggested" && at(off, @"E:\Saves\A").Status == "suggested" && at(off, @"C:\Users\Alex\Documents\My Games\A").Status == "covered", "game saves: Saved Games and Vault folders suggested, one inside Documents 'covered'");
            Ok(at(off, @"F:\More") == null && at(off, @"C:\Users\Alex\Documents\My Games") != null, "folders that don't exist aren't suggested; My Games is listed when it exists");
            var on = Ransom.Suggest(new CfaFacts { Read = true, Mode = 1, Protected = { @"E:\Saves" } }, k, vf, p => true);
            Ok(at(on, k.Documents).Status == "protected" && at(on, @"E:\Saves\A").Status == "covered" && at(on, k.SavedGames).Status == "suggested", "CFA on with E:\\Saves added: defaults protected, E:\\Saves\\A covered, Saved Games still suggested");
            Ok(on.Where(h => h.Status == "suggested" || h.Status == "covered").All(h => h.Note.Contains("allow") || h.Note.Contains("allowed")), "every game-save suggestion says games may need to be allowed");
        }

        // ---------------- connection tables (the raw bytes GetExtendedTcpTable / GetExtendedUdpTable return)
        static void U32(List<byte> b, uint v) { b.AddRange(BitConverter.GetBytes(v)); }
        static void Ip4(List<byte> b, string ip) { b.AddRange(System.Net.IPAddress.Parse(ip).GetAddressBytes()); }
        static void Ip6(List<byte> b, string ip) { b.AddRange(System.Net.IPAddress.Parse(ip).GetAddressBytes()); }
        static void Port(List<byte> b, int p) { b.Add((byte)(p >> 8)); b.Add((byte)(p & 0xFF)); b.Add(0); b.Add(0); }
        static byte[] Tcp4(params object[][] rows)
        {
            var b = new List<byte>(); U32(b, (uint)rows.Length);
            foreach (var r in rows) { U32(b, Convert.ToUInt32(r[0])); Ip4(b, (string)r[1]); Port(b, (int)r[2]); Ip4(b, (string)r[3]); Port(b, (int)r[4]); U32(b, Convert.ToUInt32(r[5])); }
            return b.ToArray();
        }
        static void Tables()
        {
            var t = NetTables.ParseTcp4(Tcp4(new object[] { 5, "192.168.1.20", 50123, "203.0.113.7", 443, 1200 }, new object[] { 2, "0.0.0.0", 445, "0.0.0.0", 0, 4 }));
            Ok(t.Count == 2 && t[0].State == 5 && t[0].LocalIp == "192.168.1.20" && t[0].LocalPort == 50123 && t[0].RemoteIp == "203.0.113.7" && t[0].RemotePort == 443 && t[0].Pid == 1200 && t[1].State == 2 && t[1].LocalPort == 445 && t[1].Pid == 4, "TCP v4 rows: state, addresses, ports (network byte order), pid");
            var b6 = new List<byte>(); U32(b6, 1); Ip6(b6, "2001:db8::5"); U32(b6, 0); Port(b6, 8080); Ip6(b6, "::"); U32(b6, 0); Port(b6, 0); U32(b6, 2); U32(b6, 777);
            var t6 = NetTables.ParseTcp6(b6.ToArray());
            Ok(t6.Count == 1 && t6[0].V6 && t6[0].LocalIp == "2001:db8::5" && t6[0].LocalPort == 8080 && t6[0].State == 2 && t6[0].Pid == 777, "TCP v6 row (56 bytes)");
            var u = new List<byte>(); U32(u, 2); Ip4(u, "0.0.0.0"); Port(u, 5353); U32(u, 900); Ip4(u, "127.0.0.1"); Port(u, 1900); U32(u, 901);
            var tu = NetTables.ParseUdp4(u.ToArray());
            Ok(tu.Count == 2 && tu[0].Proto == "UDP" && tu[0].LocalPort == 5353 && tu[1].Pid == 901, "UDP v4 rows");
            var u6 = new List<byte>(); U32(u6, 1); Ip6(u6, "::"); U32(u6, 0); Port(u6, 3478); U32(u6, 42);
            Ok(NetTables.ParseUdp6(u6.ToArray()).Single().LocalPort == 3478, "UDP v6 row (28 bytes)");
            var bad = Tcp4(new object[] { 5, "10.0.0.2", 1, "10.0.0.3", 2, 3 }); bad[0] = 50;   // claims 50 rows, has 1
            Ok(NetTables.ParseTcp4(bad).Count == 1 && NetTables.ParseTcp4(new byte[2]).Count == 0, "a short or lying table never reads past the end");
            Ok(NetView.IsLan("192.168.0.4") && NetView.IsLan("10.1.2.3") && NetView.IsLan("172.20.0.1") && NetView.IsLan("fe80::1%12") && !NetView.IsLan("203.0.113.9") && !NetView.IsLan("172.32.0.1") && NetView.IsLoopback("::1") && NetView.IsLoopback("127.0.0.1"), "local network vs internet vs loopback");
        }

        static PathRoots Roots() { return new PathRoots { Temp = @"C:\Users\Alex\AppData\Local\Temp\", Roaming = @"C:\Users\Alex\AppData\Roaming", Local = @"C:\Users\Alex\AppData\Local", Downloads = @"C:\Users\Alex\Downloads", Windows = @"C:\Windows", HallowPrograms = @"C:\Users\Alex\AppData\Local\Programs" }; }
        static Dictionary<int, ProcInfo> Procs()
        {
            return new Dictionary<int, ProcInfo> {
                { 4, new ProcInfo { Pid = 4 } },
                { 100, new ProcInfo { Pid = 100, Name = "chrome", Path = @"C:\Program Files\Google\Chrome\Application\chrome.exe", Signer = "Google LLC" } },
                { 101, new ProcInfo { Pid = 101, Name = "chrome", Path = @"C:\Program Files\Google\Chrome\Application\chrome.exe", Signer = "Google LLC" } },
                { 200, new ProcInfo { Pid = 200, Name = "updsvc", Path = @"C:\Users\Alex\AppData\Local\Temp\x\updsvc.exe" } },
                { 201, new ProcInfo { Pid = 201, Name = "helper", Path = @"C:\Users\Alex\AppData\Roaming\helper\helper.exe" } },
                { 300, new ProcInfo { Pid = 300, Name = "svchost", Path = @"C:\Windows\System32\svchost.exe" } },
                { 400, new ProcInfo { Pid = 400, Name = "mshare", Path = @"C:\Program Files\MediaShare\mshare.exe", Signer = "Example Media Ltd" } },
                { 500, new ProcInfo { Pid = 500, Name = "HallowRemote", Path = @"C:\Users\Alex\AppData\Local\Programs\Hallow Remote\HallowRemote.exe" } },
                { 600, new ProcInfo { Pid = 600, Name = "devserver", Path = @"C:\Users\Alex\AppData\Local\Temp\dev\devserver.exe" } } };
        }
        static List<ConnRow> FakeRows()
        {
            Func<string, int, string, int, string, int, int, ConnRow> R = (pr, st, l, lp, rip, rp, pid) => new ConnRow { Proto = pr, State = st, LocalIp = l, LocalPort = lp, RemoteIp = rip, RemotePort = rp, Pid = pid };
            return new List<ConnRow> {
                R("TCP", 5, "192.168.1.20", 50001, "203.0.113.7", 443, 100), R("TCP", 5, "192.168.1.20", 50002, "203.0.113.7", 443, 101), R("TCP", 5, "192.168.1.20", 50003, "198.51.100.9", 443, 100),
                R("TCP", 5, "192.168.1.20", 50004, "192.168.1.1", 8443, 100), R("TCP", 5, "127.0.0.1", 50005, "127.0.0.1", 9222, 100), R("TCP", 6, "192.168.1.20", 50006, "203.0.113.99", 80, 100),
                R("TCP", 5, "::ffff:192.168.1.20", 50007, "::ffff:203.0.113.8", 443, 200),
                R("TCP", 2, "0.0.0.0", 445, "0.0.0.0", 0, 4), R("TCP", 2, "0.0.0.0", 4444, "0.0.0.0", 0, 200), R("UDP", 0, "0.0.0.0", 4444, null, 0, 200),
                R("TCP", 2, "127.0.0.1", 6463, "0.0.0.0", 0, 201), R("TCP", 2, "::", 135, "::", 0, 300), R("TCP", 2, "192.168.1.20", 8200, "0.0.0.0", 0, 400), R("UDP", 0, "192.168.1.20", 1900, null, 0, 400),
                R("TCP", 2, "0.0.0.0", 7000, "0.0.0.0", 0, 500), R("UDP", 0, "127.0.0.1", 5000, null, 0, 600), R("TCP", 2, "0.0.0.0", 3000, "0.0.0.0", 0, 999) };
        }
        static void Listeners()
        {
            var procs = Procs(); Func<int, ProcInfo> proc = pid => procs.ContainsKey(pid) ? procs[pid] : null;
            var apps = NetView.Apps(FakeRows(), proc);
            var chrome = apps.First(a => a.Name == "chrome");
            Ok(chrome.Pids.Count == 2 && chrome.Connections == 4 && chrome.Remotes.Count == 2 && chrome.Lan == 1, "apps: chrome's two processes in one row, 4 connections (loopback and closing ones left out), 2 internet hosts, 1 on the LAN");
            Ok(apps.First(a => a.Name == "updsvc").Remotes.Single() == "203.0.113.8", "IPv4-mapped IPv6 addresses shown as IPv4");
            Ok(apps.Count == 2, "only programs with established connections to other machines");
            var ls = NetView.Listeners(FakeRows(), proc, null, Roots(), p => true);
            Func<string, Listener> L = n => ls.FirstOrDefault(x => x.Name == n);
            Ok(L("helper") == null && L("devserver") == null, "listeners bound to loopback only (inside the PC) aren't listed");
            Ok(L("updsvc") != null && L("updsvc").V == Verdict.Suspicious && L("updsvc").Ports.SequenceEqual(new[] { "TCP 4444", "UDP 4444" }) && L("updsvc").Reason.Contains("Temp"), "unsigned listener in Temp: suspicious, TCP and UDP ports merged");
            Ok(ls[0].Name == "updsvc", "suspicious listeners come first");
            Ok(L("System (Windows)").V == Verdict.KnownGood && L("svchost").V == Verdict.KnownGood && L("svchost").Reason.Contains("Windows"), "System (pid 4) and catalog-signed Windows parts: known good");
            Ok(L("mshare").V == Verdict.Unknown && !L("mshare").AllNetworks && L("mshare").Ports.Count == 2, "signed by an unknown publisher: unknown; bound to one address");
            Ok(L("HallowRemote").V == Verdict.KnownGood, "a Hallow app listening (Hallow Remote): known good");
            Ok(L("process 999") != null && L("process 999").V == Verdict.Unknown && L("process 999").Path == null, "a process Windows won't name: unknown, no buttons for a file");
            var l2 = new Listener { Name = "x", Path = @"C:\Users\Alex\AppData\Roaming\x\x.exe", Pids = { 7 } }; string why;
            Ok(NetView.Classify(l2, Roots(), out why) == Verdict.Suspicious, "unsigned listener in AppData: suspicious");
            l2.Signer = "Some Studio"; Ok(NetView.Classify(l2, Roots(), out why) == Verdict.Unknown, "signed listener in AppData: not suspicious");
            var snap = new NetSnapshot { Listeners = ls, Apps = apps };
            var ch = NetView.Evaluate(snap);
            Ok(ch.State == CheckState.Bad && ch.Penalty == 6 && ch.Line.Contains("updsvc") && ch.FixAction == "page:network", "network check: a suspicious listener costs 6 and points to the Network page");
            snap.Listeners = ls.Where(x => x.V != Verdict.Suspicious).ToList(); ch = NetView.Evaluate(snap);
            Ok(ch.State == CheckState.Good && ch.Penalty == 0 && ch.FixAction == null, "network check: no suspicious listener - good, nothing to do");
            Ok(NetView.Evaluate(new NetSnapshot { Error = "x" }).State == CheckState.Unknown, "network check: tables unreadable - unknown");
        }

        // ---------------- Windows Firewall (fake rules)
        static void Firewall()
        {
            Ok(NetView.PortMatches("80,443,5000-5010", 5005) && NetView.PortMatches("*", 1) && NetView.PortMatches("Any", 1) && !NetView.PortMatches("80,443", 8080) && !NetView.PortMatches("RPC", 135), "firewall port lists: numbers, ranges, any; keywords don't match");
            var fw = new FwFacts { Read = true };
            fw.Enabled[2] = true; fw.Enabled[4] = true; fw.DefaultAllow[2] = false; fw.DefaultAllow[4] = false;
            var app = @"C:\Games\Game\game.exe";
            fw.Rules.Add(new FwRule { Name = "Game", App = @"C:\Games\Game\game.exe", Ports = "*", Protocol = 256, Profiles = 2, Allow = true });
            var tcp = new List<Tuple<string, int>> { Tuple.Create("TCP", 7777) };
            var a = NetView.Firewall(app, false, tcp, fw);
            Ok(a.Private == "allowed" && a.Public == "blocked", "an allow rule for private only: let in at home, blocked on public Wi-Fi");
            fw.Rules.Add(new FwRule { Name = "Game (all)", App = "%SystemDrive%\\Games\\Game\\game.exe", Ports = "7777", Protocol = 6, Profiles = 0x7FFFFFFF, Allow = true });
            Ok(NetView.Firewall(app, false, tcp, fw).Public == "allowed", "rule paths with %variables% match");
            fw.Rules.Add(new FwRule { Name = "Block game public", App = app, Ports = "*", Protocol = 256, Profiles = 4, Allow = false });
            a = NetView.Firewall(app, false, tcp, fw);
            Ok(a.Public == "blocked" && a.Private == "allowed", "a block rule wins over allow rules");
            fw.Rules.Add(new FwRule { Name = "Off rule", App = @"C:\Other\o.exe", Ports = "*", Profiles = 0x7FFFFFFF, Allow = true, Enabled = false });
            Ok(NetView.Firewall(@"C:\Other\o.exe", false, tcp, fw).Private == "blocked", "disabled rules don't count; no rule = blocked (default inbound block)");
            fw.Rules.Add(new FwRule { Name = "Port 3000 any app", App = null, Ports = "3000", Protocol = 6, Profiles = 2, Allow = true });
            Ok(NetView.Firewall(@"C:\Dev\d.exe", false, new List<Tuple<string, int>> { Tuple.Create("TCP", 3000) }, fw).Private == "allowed" && NetView.Firewall(@"C:\Dev\d.exe", false, new List<Tuple<string, int>> { Tuple.Create("UDP", 3000) }, fw).Private == "blocked", "a port rule for any program: by port and protocol");
            fw.Rules.Add(new FwRule { Name = "File sharing", App = "System", Ports = "445", Protocol = 6, Profiles = 2, Allow = true });
            Ok(NetView.Firewall(null, true, new List<Tuple<string, int>> { Tuple.Create("TCP", 445) }, fw).Private == "allowed", "rules for 'System' match pid 4");
            fw.Enabled[4] = false; Ok(NetView.Firewall(@"C:\Other\o.exe", false, tcp, fw).Public == "off", "firewall off for public: everything gets in");
            Ok(NetView.FirewallText(new FwAccess { Private = "allowed", Public = "off" }).Contains("private and public") && NetView.FirewallText(new FwAccess { Private = "blocked", Public = "blocked" }).Contains("blocked") && NetView.FirewallText(new FwAccess()).Contains("couldn't"), "firewall in plain words");
            Ok(NetView.Firewall(app, false, tcp, new FwFacts()).Private == null, "firewall unreadable: unknown, not 'blocked'");
        }

        // ---------------- browser extensions (fake profile folders)
        static string Hash(string f) { using (var s = SHA256.Create()) return BitConverter.ToString(s.ComputeHash(File.ReadAllBytes(f))); }
        static string Manifest(string name, string ver, string perms, string hosts = "[]", string update = null, string extra = "")
        { return "{\"manifest_version\":3,\"name\":\"" + name + "\",\"version\":\"" + ver + "\",\"permissions\":" + perms + ",\"host_permissions\":" + hosts + (update == null ? "" : ",\"update_url\":\"" + update + "\"") + extra + "}"; }
        static string Packed(string prof, string id, string ver, string manifest, DateTime? folderTime = null)
        {
            var d = Path.Combine(prof, "Extensions", id, ver); Directory.CreateDirectory(d); File.WriteAllText(Path.Combine(d, "manifest.json"), manifest);
            if (folderTime != null) { File.SetLastWriteTime(Path.Combine(d, "manifest.json"), folderTime.Value); Directory.SetLastWriteTime(d, folderTime.Value); }
            return d;
        }
        static string Us(DateTime t) { return (t.ToUniversalTime().ToFileTimeUtc() / 10).ToString(); }
        static void Extensions()
        {
            var now = new DateTime(2026, 11, 20, 12, 0, 0);
            const string cws = "https://clients2.google.com/service/update2/crx";
            var chrome = Path.Combine(Root, "Browsers", "Chrome", "User Data"); var prof = Path.Combine(chrome, "Default"); Directory.CreateDirectory(prof);
            Directory.CreateDirectory(Path.Combine(chrome, "System Profile"));   // not a real profile: skipped
            Packed(prof, "aaaastore", "1.0_0", Manifest("Tab Tidy", "1.0", "[\"tabs\",\"storage\"]", "[]", cws));
            Packed(prof, "bbbbsideload", "2.0_0", Manifest("PDF Tools Pro", "2.0", "[\"cookies\",\"history\"]", "[\"<all_urls>\"]"));
            Packed(prof, "ccccold", "0.9_0", Manifest("Old Helper", "0.9", "[\"storage\"]", "[]", cws), now.AddDays(-500));
            Packed(prof, "ddddblocker", "5.1_0", Manifest("Block Lite", "5.1", "[\"declarativeNetRequest\",\"storage\"]", "[\"<all_urls>\"]", cws));
            Packed(prof, "eeeecomponent", "1.0", Manifest("Built-in Thing", "1.0", "[\"debugger\"]", "[\"<all_urls>\"]"));
            Packed(prof, "ffffdebug", "1.0_0", Manifest("Page Inspector", "1.0", "[\"debugger\"]", "[\"*://*/*\"]", cws));
            Packed(prof, "gggglocale", "3.0_0", Manifest("__MSG_appName__", "3.0", "[]", "[]", cws, ",\"default_locale\":\"en\""));
            Directory.CreateDirectory(Path.Combine(prof, @"Extensions\gggglocale\3.0_0\_locales\en")); File.WriteAllText(Path.Combine(prof, @"Extensions\gggglocale\3.0_0\_locales\en\messages.json"), "{\"appName\":{\"message\":\"Translated Name\"}}");
            Packed(prof, "hhhhtheme", "1.0_0", "{\"name\":\"Dark Theme\",\"version\":\"1.0\",\"theme\":{\"colors\":{}}}");
            var unpacked = Path.Combine(Root, "dev", "hallow-keys-ext"); Directory.CreateDirectory(unpacked);
            File.WriteAllText(Path.Combine(unpacked, "manifest.json"), Manifest("Hallow Keys", "2.8", "[\"nativeMessaging\",\"storage\"]", "[\"<all_urls>\"]"));
            var unpacked2 = Path.Combine(Root, "dev", "grabber"); Directory.CreateDirectory(unpacked2);
            File.WriteAllText(Path.Combine(unpacked2, "manifest.json"), Manifest("Grabber", "0.1", "[\"proxy\"]", "[\"*://*/*\"]"));
            var prefs = "{\"extensions\":{\"settings\":{" +
                "\"aaaastore\":{\"location\":1,\"from_webstore\":true,\"path\":\"aaaastore\\\\1.0_0\",\"last_update_time\":\"" + Us(now.AddDays(-10)) + "\"}," +
                "\"bbbbsideload\":{\"location\":3,\"from_webstore\":false,\"path\":\"bbbbsideload\\\\2.0_0\",\"last_update_time\":\"" + Us(now.AddDays(-20)) + "\"}," +
                "\"ddddblocker\":{\"location\":1,\"from_webstore\":true,\"path\":\"ddddblocker\\\\5.1_0\",\"disable_reasons\":[1]}," +
                "\"eeeecomponent\":{\"location\":5,\"path\":\"eeeecomponent\\\\1.0\"}," +
                "\"ffffdebug\":{\"location\":1,\"from_webstore\":true,\"path\":\"ffffdebug\\\\1.0_0\",\"last_update_time\":\"" + Us(now.AddDays(-5)) + "\"}," +
                "\"kkkkkeys\":{\"location\":4,\"path\":\"" + unpacked.Replace("\\", "\\\\") + "\"}," +
                "\"mmmmgrab\":{\"location\":4,\"path\":\"" + unpacked2.Replace("\\", "\\\\") + "\"}}}}";
            File.WriteAllText(Path.Combine(prof, "Secure Preferences"), prefs);
            File.WriteAllText(Path.Combine(prof, "Preferences"), "{\"extensions\":{\"settings\":{\"ccccold\":{\"location\":1,\"from_webstore\":true}}}}");
            var before = Directory.GetFiles(Path.Combine(Root, "Browsers"), "*", SearchOption.AllDirectories).ToDictionary(f => f, Hash);
            var l = ExtScan.Chromium("Chrome", chrome, false, Path.Combine(Root, "copies"), now);
            Func<string, ExtInfo> E = n => l.FirstOrDefault(x => x.Name == n);
            Ok(E("Tab Tidy") != null && E("Tab Tidy").Risk == "Low" && E("Tab Tidy").FromStore && E("Tab Tidy").Profile == "Default", "store extension with limited access: Low");
            Ok(E("PDF Tools Pro").Risk == "High" && E("PDF Tools Pro").Source == "sideloaded" && E("PDF Tools Pro").Reasons.Any(r => r.Contains("sideloaded")) && E("PDF Tools Pro").Reasons.Any(r => r.Contains("cookies")) && E("PDF Tools Pro").Reasons.Any(r => r.Contains("every website")), "sideloaded (location 3) with all sites + cookies + history: High, with each reason");
            Ok(E("Old Helper").Updated != null && E("Old Helper").UpdatedFromFolder && E("Old Helper").Reasons.Any(r => r.Contains("over a year")), "no update time in Preferences: the folder's date - 500 days old counts");
            Ok(E("Block Lite").Risk == "Medium" && !E("Block Lite").Enabled && E("Block Lite").Sensitive.Contains("declarativeNetRequest"), "declarativeNetRequest + all sites: Medium; switched off is noticed");
            Ok(E("Built-in Thing") == null, "component extensions (part of the browser) are skipped");
            Ok(E("Page Inspector").Risk == "High" && E("Page Inspector").FromStore, "debugger on every site: High even from the store");
            Ok(E("Translated Name") != null, "__MSG_ names are read from _locales");
            Ok(E("Dark Theme") == null, "themes are skipped");
            Ok(E("Hallow Keys") != null && E("Hallow Keys").Risk == "Known" && E("Hallow Keys").Known && E("Hallow Keys").Reasons[0].Contains("expected") && E("Hallow Keys").Source == "unpacked", "Hallow Keys (unpacked, every site, native messaging): Known, with why");
            Ok(E("Grabber").Risk == "High" && E("Grabber").Reasons.Any(r => r.Contains("unpacked")) && E("Grabber").Reasons.Any(r => r.Contains("proxy")), "unpacked with all sites + proxy: High");
            // Edge: Preferences locked by the browser (no sharing) -> the Extensions folder still works; a broken manifest is skipped
            var edge = Path.Combine(Root, "Browsers", "Edge", "User Data"); var eprof = Path.Combine(edge, "Profile 1"); Directory.CreateDirectory(eprof);
            Packed(eprof, "nnnnedgestore", "1.2_0", Manifest("Edge Notes", "1.2", "[\"storage\"]", "[]", "https://edge.microsoft.com/extensionwebstorebase/v1/crx"));
            Packed(eprof, "oooobroken", "1.0_0", "{ this is not json");
            Packed(eprof, "ppppshield", "1.1_0", Manifest("Hallow Shield", "1.1", "[\"declarativeNetRequest\"]", "[\"<all_urls>\"]"));
            var ep = Path.Combine(eprof, "Preferences"); File.WriteAllText(ep, "{\"extensions\":{\"settings\":{}}}");
            List<ExtInfo> le;
            using (new FileStream(ep, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) le = ExtScan.Chromium("Edge", edge, false, Path.Combine(Root, "copies"), now);
            Ok(le.Count == 2 && le.Any(x => x.Name == "Edge Notes" && x.FromStore && x.Profile == "Profile 1") && le.Any(x => x.Name == "Hallow Shield" && x.Risk == "Known"), "Edge: locked Preferences and a broken manifest are tolerated; store found from update_url; Hallow Shield Known");
            // Opera: the user data folder is the profile
            var opera = Path.Combine(Root, "Browsers", "Opera Stable"); Directory.CreateDirectory(opera);
            Packed(opera, "qqqqopera", "1.0_0", Manifest("Opera Thing", "1.0", "[\"tabs\"]", "[]", "https://extension-updates.opera.com/api/omaha/update/"));
            var lo = ExtScan.Chromium("Opera", opera, true, Path.Combine(Root, "copies"), now);
            Ok(lo.Count == 1 && lo[0].FromStore && lo[0].Profile == "", "Opera (single profile folder): found, from Opera's store");
            Ok(ExtScan.Chromium("Brave", Path.Combine(Root, "Browsers", "Brave", "nope"), false, Path.Combine(Root, "copies"), now).Count == 0, "a browser that isn't installed: nothing");
            var after = Directory.GetFiles(Path.Combine(Root, "Browsers"), "*", SearchOption.AllDirectories).ToDictionary(f => f, Hash);
            Ok(before.Count <= after.Count && before.All(kv => after.ContainsKey(kv.Key) && after[kv.Key] == kv.Value) && after.Keys.All(k => before.ContainsKey(k) || k.StartsWith(eprof) || k.StartsWith(opera)), "the browser files were never changed (same bytes, nothing added)");
            Ok(!Directory.Exists(Path.Combine(Root, "copies")) || Directory.GetFiles(Path.Combine(Root, "copies")).Length == 0, "copies of browser files are deleted after reading");
            var sorted = ExtScan.Sorted(l.Concat(le));
            Ok(ExtScan.RiskRank(sorted.First().Risk) == 0 && sorted.Last().Risk == "Known", "sorted: High first, Known last");
            Ok(ExtScan.ExtensionsUrl("Edge") == "edge://extensions/" && ExtScan.ExtensionsUrl("Brave") == "brave://extensions/" && ExtScan.ExtensionsUrl("Firefox") == "about:addons" && ExtScan.ExtensionsUrl("Chrome") == "chrome://extensions/", "each browser's own extensions page");
            var ch = ExtScan.Evaluate(sorted);
            int highOn = sorted.Count(x => x.Risk == "High" && x.Enabled);
            Ok(ch.State == CheckState.Warn && ch.Penalty == Math.Min(6, highOn * 3) && ch.FixAction == "page:extensions", "extensions check: 3 points per high-risk extension, at most 6 (" + highOn + " high)");
            var med = new ExtInfo { Name = "Ad Blocker", Source = "store", FromStore = true }; ExtScan.Rate(med, new[] { "<all_urls>", "cookies" }, now);
            var noHigh = sorted.Where(x => x.Risk != "High").Concat(new[] { med }).ToList();
            Ok(med.Risk == "Medium" && ExtScan.Evaluate(noHigh).Penalty == 0 && ExtScan.Evaluate(noHigh).State == CheckState.Info, "a store extension with all sites + cookies is Medium: worth a look, no points");
            Ok(ExtScan.Evaluate(sorted.Where(x => x.Known).ToList()).State == CheckState.Good, "only Hallow Keys / Shield: good");
            var off = new ExtInfo { Name = "Off one", Source = "unpacked", Enabled = false }; ExtScan.Rate(off, new[] { "<all_urls>" }, now);
            Ok(off.Risk == "High" && ExtScan.Evaluate(new List<ExtInfo> { off }).Penalty == 0, "a switched-off risky extension is listed but costs nothing");
        }
        static void Firefox()
        {
            var now = new DateTime(2026, 11, 20, 12, 0, 0);
            var ff = Path.Combine(Root, "Firefox", "Profiles"); var p = Path.Combine(ff, "abcd.default-release"); Directory.CreateDirectory(p);
            Func<DateTime, long> ms = t => (long)(t.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
            File.WriteAllText(Path.Combine(p, "extensions.json"), "{\"addons\":[" +
                "{\"id\":\"amo@example.org\",\"type\":\"extension\",\"location\":\"app-profile\",\"version\":\"1.0\",\"active\":true,\"signedState\":2,\"sourceURI\":\"https://addons.mozilla.org/firefox/downloads/file/1/x.xpi\",\"updateDate\":" + ms(now.AddDays(-3)) + ",\"defaultLocale\":{\"name\":\"Store Helper\"},\"userPermissions\":{\"permissions\":[\"storage\"],\"origins\":[]}}," +
                "{\"id\":\"side@example.org\",\"type\":\"extension\",\"location\":\"app-profile\",\"version\":\"0.3\",\"active\":true,\"signedState\":2,\"foreignInstall\":true,\"updateDate\":" + ms(now.AddDays(-700)) + ",\"defaultLocale\":{\"name\":\"Side Bar Deals\"},\"userPermissions\":{\"permissions\":[\"cookies\"],\"origins\":[\"<all_urls>\"]}}," +
                "{\"id\":\"builtin@mozilla.org\",\"type\":\"extension\",\"location\":\"app-builtin\",\"defaultLocale\":{\"name\":\"Built-in\"}}," +
                "{\"id\":\"dict@x\",\"type\":\"dictionary\",\"location\":\"app-profile\",\"defaultLocale\":{\"name\":\"Dictionary\"}}]}");
            var l = ExtScan.Firefox(ff, Path.Combine(Root, "copies"), now);
            Ok(l.Count == 2 && l.Any(x => x.Name == "Store Helper" && x.Risk == "Low" && x.FromStore), "Firefox: an addons.mozilla.org extension with little access is Low; built-ins and dictionaries skipped");
            var s = l.FirstOrDefault(x => x.Name == "Side Bar Deals");
            Ok(s != null && s.Risk == "High" && s.Source == "sideloaded" && s.Reasons.Any(r => r.Contains("over a year")), "Firefox: a foreign install with all sites and an old update date: High");
            var locked = Path.Combine(p, "extensions.json");
            using (new FileStream(locked, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) Ok(ExtScan.Firefox(ff, Path.Combine(Root, "copies"), now).Count == 0, "Firefox: a locked extensions.json is skipped without an error");
            Ok(ExtScan.Firefox(Path.Combine(Root, "nope"), Path.Combine(Root, "copies"), now).Count == 0, "no Firefox: nothing");
            var all = ExtScan.All(new ExtEnv { FirefoxProfiles = ff, TempDir = Path.Combine(Root, "copies"), Chromium = { new[] { "Chrome", Path.Combine(Root, "Browsers", "Chrome", "User Data"), "" } } }, now);
            Ok(all.Any(x => x.Browser == "Firefox") && all.Any(x => x.Browser == "Chrome"), "all browsers together");
        }

        // ---------------- the family score with the new group, and the to-do list
        static void Numbers()
        {
            var more = MoreScore.Evaluate(FakeExtras.Network(), FakeExtras.Extensions());
            Ok(more.Sum(c => c.Penalty) == 12 && MoreScore.Penalty(more) == 10 && MoreScore.GroupScore(more) == 88, "made-up network + extensions: 6 + 6 points, capped at 10 for the family score");
            Ok(FamilyScore.Combined(90, null, more) == 80 && FamilyScore.Combined(5, null, more) == 0 && FamilyScore.Combined(-1, null, more) == -1 && FamilyScore.Combined(90, null, null) == 90, "family score: Windows minus apps minus Network & browsers, never below 0");
            Ok(MoreScore.GroupScore(null) == null && MoreScore.Penalty(null) == 0, "not looked at yet: no points");
            var win = Score.Evaluate(FakeProbe.Sample(), null);
            var todo = FamilyScore.Todo(win.Concat(more), 10);
            Ok(todo.Any(c => c.Id == "listeners") && todo.Any(c => c.Id == "extensions") && todo.Any(c => c.Id == "cfa"), "the to-do list includes listeners, extensions and ransomware protection");
            Ok(todo.FindIndex(c => c.Id == "listeners") < todo.FindIndex(c => c.Id == "cfa"), "to-do: more points first (listeners 6 before ransomware 3)");
            Ok(FakeExtras.Network().Apps.SelectMany(a => a.Remotes).All(ip => ip.StartsWith("203.0.113.") || ip.StartsWith("198.51.100.") || ip.StartsWith("192.0.2.")), "--snap addresses are documentation addresses only (never real ones)");
        }

        // ---------------- --real-timing: the real read-only checks once, timed (prints counts only - no names, paths or addresses)
        public static int RealTiming()
        {
            var sw = Stopwatch.StartNew(); var cfa = new WindowsCfa().Read(); long tCfa = sw.ElapsedMilliseconds;
            Console.WriteLine("cfa: " + tCfa + " ms, read " + cfa.Read + ", mode " + Ransom.ModeWord(cfa.Mode) + ", " + cfa.Protected.Count + " folders, " + cfa.Allowed.Count + " apps, lists hidden " + cfa.ListsHidden);
            sw.Restart(); var rows = NetTables.Read(); long tRows = sw.ElapsedMilliseconds;
            sw.Restart(); var fw = WindowsNet.ReadFirewall(); long tFw = sw.ElapsedMilliseconds;
            sw.Restart(); var net = new WindowsNet().Read(); long tNet = sw.ElapsedMilliseconds;
            Console.WriteLine("tables: " + tRows + " ms, " + rows.Count + " rows; firewall: " + tFw + " ms, read " + fw.Read + ", " + fw.Rules.Count + " inbound rules; whole network view: " + tNet + " ms, " + net.Apps.Count + " apps, " + net.Listeners.Count + " listeners (" + net.Listeners.Count(l => l.V == Verdict.Suspicious) + " suspicious, " + net.Listeners.Count(l => l.Fw != null && l.Fw.Private != null) + " with a firewall answer)");
            sw.Restart(); var ex = ExtScan.All(ExtEnv.Real(), DateTime.Now); long tExt = sw.ElapsedMilliseconds;
            Console.WriteLine("extensions: " + tExt + " ms, " + ex.Count + " (" + string.Join(", ", new[] { "High", "Medium", "Low", "Known" }.Select(r => ex.Count(x => x.Risk == r) + " " + r)) + ") in " + ex.Select(x => x.Browser).Distinct().Count() + " browsers");
            return 0;
        }
    }
}
