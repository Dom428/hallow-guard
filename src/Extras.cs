// Hallow Guard v1.2 - the "Network & browsers" group of the family score (programs open to the network, browser extensions) and
// the made-up network / extension / ransomware data for --snap pictures and developer tests (never this PC's real names,
// addresses or extensions).
using System;
using System.Collections.Generic;
using System.Linq;

namespace HallowGuard
{
    public static class MoreScore
    {
        public const int Cap = 10;
        public static List<Check> Evaluate(NetSnapshot net, List<ExtInfo> exts)
        {
            return new List<Check> { NetView.Evaluate(net), ExtScan.Evaluate(exts) };
        }
        public static int Penalty(List<Check> more) { return more == null ? 0 : Math.Min(Cap, more.Sum(c => c.Penalty)); }
        public static int? GroupScore(List<Check> more) { if (more == null) return null; return Math.Max(0, 100 - more.Sum(c => c.Penalty)); }
    }

    public interface IExtSource { List<ExtInfo> Read(); }
    public class WindowsExts : IExtSource { public List<ExtInfo> Read() { return ExtScan.All(ExtEnv.Real(), DateTime.Now); } }

    public class FakeNet : INetSource { public NetSnapshot Read() { return FakeExtras.Network(); } }
    public class FakeExts : IExtSource { public List<ExtInfo> Read() { return FakeExtras.Extensions(); } }
    public class FakeCfa : ICfaSource { public CfaFacts Read() { return FakeExtras.Cfa(); } }

    public static class FakeExtras
    {
        public static CfaFacts Cfa() { return new CfaFacts { Read = true, Mode = 0, Allowed = { @"C:\Program Files\Steam\steam.exe" } }; }
        public static KnownFolders Folders() { return new KnownFolders { Documents = @"C:\Users\Alex\Documents", Pictures = @"C:\Users\Alex\Pictures", Desktop = @"C:\Users\Alex\Desktop", SavedGames = @"C:\Users\Alex\Saved Games" }; }
        public static List<string> VaultFolders() { return new List<string> { @"C:\Users\Alex\AppData\LocalLow\Example Studio\Example Game", @"C:\Users\Alex\Documents\My Games\Example RPG" }; }
        public static List<FolderHint> Hints() { return Ransom.Suggest(Cfa(), Folders(), VaultFolders(), p => true); }

        public static NetSnapshot Network()
        {
            var fwPriv = new FwAccess { Private = "allowed", Public = "blocked" };
            var s = new NetSnapshot { FirewallRead = true, Rows = 214, When = DateTime.Now.AddMinutes(-2) };
            s.Listeners.Add(new Listener { Name = "updsvc", Path = @"C:\Users\Alex\AppData\Local\Temp\updsvc\updsvc.exe", Pids = { 7716 }, Ports = { "TCP 4444" }, AllNetworks = true, Fw = new FwAccess { Private = "allowed", Public = "allowed" }, V = Verdict.Suspicious, Reason = "Not signed and runs from Temp, but waits for connections from the network - malware often looks like this.", Exists = true });
            s.Listeners.Add(new Listener { Name = "MediaShare", Path = @"C:\Program Files\MediaShare\mshare.exe", Signer = "Example Media Ltd", Pids = { 5120 }, Ports = { "TCP 8200", "UDP 1900" }, AllNetworks = true, Fw = fwPriv, V = Verdict.Unknown, Reason = "Signed by Example Media Ltd - check you recognise it.", Exists = true });
            s.Listeners.Add(new Listener { Name = "Spotify", Path = @"C:\Users\Alex\AppData\Roaming\Spotify\Spotify.exe", Signer = "Spotify AB", Pids = { 9012 }, Ports = { "TCP 57621", "UDP 57621", "UDP 1900" }, AllNetworks = true, Fw = fwPriv, V = Verdict.KnownGood, Reason = "Signed by Spotify AB.", Exists = true });
            s.Listeners.Add(new Listener { Name = "steam", Path = @"C:\Program Files (x86)\Steam\steam.exe", Signer = "Valve Corp.", Pids = { 6604 }, Ports = { "TCP 27036", "UDP 27036" }, AllNetworks = true, Fw = fwPriv, V = Verdict.KnownGood, Reason = "Signed by Valve Corp.", Exists = true });
            s.Listeners.Add(new Listener { Name = "System (Windows)", Pids = { 4 }, Ports = { "TCP 139", "TCP 445" }, Fw = new FwAccess { Private = "allowed", Public = "blocked" }, V = Verdict.KnownGood, Reason = "Windows itself (file and printer sharing, network discovery and similar)." });
            s.Apps.Add(new NetApp { Name = "chrome", Path = @"C:\Program Files\Google\Chrome\Application\chrome.exe", Pids = { 3120, 3388 }, Connections = 23, Remotes = { "203.0.113.10", "198.51.100.69", "192.0.2.129", "203.0.113.17", "198.51.100.44", "203.0.113.90" } });
            s.Apps.Add(new NetApp { Name = "steam", Path = @"C:\Program Files (x86)\Steam\steam.exe", Pids = { 6604 }, Connections = 4, Remotes = { "198.51.100.12", "198.51.100.13" }, Lan = 1 });
            s.Apps.Add(new NetApp { Name = "Discord", Path = @"C:\Users\Alex\AppData\Local\Discord\app-1.0.9200\Discord.exe", Pids = { 8800 }, Connections = 3, Remotes = { "203.0.113.200", "203.0.113.201" } });
            s.Apps.Add(new NetApp { Name = "updsvc", Path = @"C:\Users\Alex\AppData\Local\Temp\updsvc\updsvc.exe", Pids = { 7716 }, Connections = 1, Remotes = { "192.0.2.66" } });
            s.Apps.Add(new NetApp { Name = "svchost", Path = @"C:\Windows\System32\svchost.exe", Pids = { 1408, 2264 }, Connections = 3, Remotes = { "192.0.2.4" }, Lan = 2 });
            return s;
        }
        public static Dictionary<string, string> Names()
        {
            return new Dictionary<string, string> { { "203.0.113.10", "example-cdn-1.example.net" }, { "198.51.100.69", "news.example.org" }, { "198.51.100.12", "content1.example.com" }, { "203.0.113.200", "voice-eu.example.chat" } };
        }

        public static List<ExtInfo> Extensions()
        {
            var now = DateTime.Now; var l = new List<ExtInfo>();
            Func<string, string, string, string, string, DateTime, string[], ExtInfo> add = (browser, name, ver, id, src, upd, perms) =>
            {
                var e = new ExtInfo { Browser = browser, Profile = "Default", Name = name, Version = ver, Id = id, Source = src, FromStore = src == "store", Updated = upd };
                ExtScan.Rate(e, perms, now); l.Add(e); return e;
            };
            add("Chrome", "Hallow Keys", "2.8", "hkhallowkeysexampleid0000000000", "unpacked", now.AddDays(-2), new[] { "<all_urls>", "nativeMessaging", "storage" });
            add("Edge", "Hallow Shield", "1.1", "hshallowshieldexampleid00000000", "unpacked", now.AddDays(-9), new[] { "<all_urls>", "declarativeNetRequest", "storage" });
            add("Chrome", "PDF Tools Pro", "3.2.1", "pdftoolsexampleid00000000000000", "sideloaded", now.AddDays(-30), new[] { "<all_urls>", "cookies", "history", "tabs" });
            add("Edge", "Video Downloader Plus", "0.9.4", "videodlexampleid000000000000000", "unpacked", now.AddDays(-500), new[] { "*://*/*", "webRequest", "webRequestBlocking", "proxy" });
            add("Chrome", "uBlock Origin Lite", "2025.1.1", "ublockliteexampleid000000000000", "store", now.AddDays(-12), new[] { "declarativeNetRequest", "<all_urls>", "storage" });
            add("Firefox", "Password Helper", "4.0", "pwhelper@example.org", "store", now.AddDays(-40), new[] { "<all_urls>", "nativeMessaging", "cookies" });
            add("Chrome", "Dark Reader", "4.9", "darkreaderexampleid000000000000", "store", now.AddDays(-20), new[] { "storage", "tabs" });
            add("Brave", "Old Tab Saver", "1.0", "tabsaverexampleid00000000000000", "store", now.AddDays(-800), new[] { "tabs", "storage" });
            return ExtScan.Sorted(l);
        }
    }
}
