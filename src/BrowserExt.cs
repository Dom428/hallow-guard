// Hallow Guard v1.2 - browser extension risk, read-only. For Chrome, Edge, Brave, Opera (GX) and Firefox profiles Guard reads each
// extension's manifest (shared read) and the browser's (Secure) Preferences / extensions.json (a COPY in Guard's temp folder);
// locked or broken files are skipped. Each extension is rated from what it can do:
//   - all-sites access (<all_urls>, *://*/* ...), sensitive permissions (debugger, proxy, nativeMessaging, webRequestBlocking,
//     cookies, history, management, declarativeNetRequest together with all sites),
//   - not from the browser's store (loaded unpacked, added by another program or by a policy - Preferences' location /
//     from_webstore, Firefox's foreignInstall / signedState),
//   - not updated in over a year (Preferences' last_update_time, else the extension folder's date).
// Hallow Keys and Hallow Shield are "Known": they need every site (filling passwords / blocking ads) and that's expected.
// Browsers are never changed; the only button opens that browser's extensions page when you click it.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace HallowGuard
{
    public class ExtInfo
    {
        public string Browser, Profile, Id, Name, Version, Dir;
        public bool FromStore, Enabled = true, AllSites, Known;
        public string Source;                  // "store", "unpacked", "sideloaded", "policy", "unknown"
        public DateTime? Updated; public bool UpdatedFromFolder;
        public List<string> Sensitive = new List<string>();
        public string Risk = "Low";            // Known | Low | Medium | High
        public List<string> Reasons = new List<string>();
        public int Points;
    }

    public class ExtEnv
    {
        public List<string[]> Chromium = new List<string[]>();   // { browser, user data folder, "single" when that folder is the profile (Opera) }
        public string FirefoxProfiles, TempDir;
        public static ExtEnv Real()
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData); var roam = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var e = new ExtEnv { FirefoxProfiles = Path.Combine(roam, @"Mozilla\Firefox\Profiles"), TempDir = Path.Combine(Path.GetTempPath(), "HallowGuard-browser-copies") };
            e.Chromium.Add(new[] { "Chrome", Path.Combine(local, @"Google\Chrome\User Data"), "" });
            e.Chromium.Add(new[] { "Edge", Path.Combine(local, @"Microsoft\Edge\User Data"), "" });
            e.Chromium.Add(new[] { "Brave", Path.Combine(local, @"BraveSoftware\Brave-Browser\User Data"), "" });
            e.Chromium.Add(new[] { "Opera", Path.Combine(roam, @"Opera Software\Opera Stable"), "single" });
            e.Chromium.Add(new[] { "Opera GX", Path.Combine(roam, @"Opera Software\Opera GX Stable"), "single" });
            return e;
        }
    }

    public static class ExtScan
    {
        public static readonly string[] KnownNames = { "Hallow Keys", "Hallow Shield" };
        public const int HighPoints = 3, MaxPoints = 6;
        static readonly string[] StoreUpdate = { "clients2.google.com/service/update2/crx", "edge.microsoft.com/extensionwebstorebase", "extension-updates.opera.com", "chromewebstore.googleapis.com" };
        // sensitive permission -> (weight, plain words)
        static readonly Dictionary<string, Tuple<int, string>> Sens = new Dictionary<string, Tuple<int, string>> {
            { "debugger", Tuple.Create(3, "can control pages like a developer tool (debugger)") },
            { "proxy", Tuple.Create(2, "can send all your browsing through another server (proxy)") },
            { "nativeMessaging", Tuple.Create(2, "can talk to programs on this PC (native messaging)") },
            { "management", Tuple.Create(2, "can switch your other extensions on and off (management)") },
            { "webRequestBlocking", Tuple.Create(1, "can stop and change web requests (webRequestBlocking)") },
            { "cookies", Tuple.Create(1, "can read your cookies - including sign-ins (cookies)") },
            { "history", Tuple.Create(1, "can read your browsing history (history)") },
            { "declarativeNetRequest", Tuple.Create(1, "can block or redirect requests on every site (declarativeNetRequest)") } };

        public static List<ExtInfo> All(ExtEnv env, DateTime now)
        {
            var r = new List<ExtInfo>();
            foreach (var b in env.Chromium) try { r.AddRange(Chromium(b[0], b[1], b[2] == "single", env.TempDir, now)); } catch { }
            try { r.AddRange(Firefox(env.FirefoxProfiles, env.TempDir, now)); } catch { }
            return Sorted(r);
        }
        public static List<ExtInfo> Sorted(IEnumerable<ExtInfo> l)
        {
            return l.OrderBy(x => RiskRank(x.Risk)).ThenBy(x => x.Enabled ? 0 : 1).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Browser).ToList();
        }
        public static int RiskRank(string r) { return r == "High" ? 0 : r == "Medium" ? 1 : r == "Low" ? 2 : 3; }

        static List<string> Profiles(string root, bool single)
        {
            var r = new List<string>();
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) return r;
            if (single) { r.Add(root); return r; }
            string[] dirs; try { dirs = Directory.GetDirectories(root); } catch { return r; }
            foreach (var d in dirs.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) { var n = Path.GetFileName(d); if (n == "Default" || n.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase)) r.Add(d); }
            return r;
        }

        // Chromium: the extension list from (Secure) Preferences (location, from_webstore, last_update_time, state), each manifest from
        // the stored copy, the unpacked folder or Extensions\<id>\<version>\; extensions not in Preferences come from Extensions\ alone
        public static List<ExtInfo> Chromium(string browser, string root, bool single, string temp, DateTime now)
        {
            var r = new List<ExtInfo>();
            foreach (var prof in Profiles(root, single))
            {
                var pname = single ? "" : Path.GetFileName(prof);
                var settings = new Dictionary<string, Dictionary<string, object>>(StringComparer.OrdinalIgnoreCase);
                foreach (var pf in new[] { "Preferences", "Secure Preferences" })   // Secure Preferences wins where both have an entry
                {
                    var s = J.Dict(J.Dict(J.Parse(ShieldScan.ReadCopy(Path.Combine(prof, pf), temp, 32 * 1024 * 1024)), "extensions"), "settings");
                    if (s != null) foreach (var kv in s) { var d = kv.Value as Dictionary<string, object>; if (d != null) settings[kv.Key] = Merge(settings.ContainsKey(kv.Key) ? settings[kv.Key] : null, d); }
                }
                var extDir = Path.Combine(prof, "Extensions");
                var ids = new HashSet<string>(settings.Keys, StringComparer.OrdinalIgnoreCase);
                try { if (Directory.Exists(extDir)) foreach (var d in Directory.GetDirectories(extDir)) ids.Add(Path.GetFileName(d)); } catch { }
                foreach (var id in ids.OrderBy(x => x))
                {
                    try
                    {
                        Dictionary<string, object> s; settings.TryGetValue(id, out s);
                        var e = FromChromium(browser, pname, id, s, extDir, temp, now);
                        if (e != null) r.Add(e);
                    }
                    catch { }
                }
            }
            return r;
        }
        static Dictionary<string, object> Merge(Dictionary<string, object> a, Dictionary<string, object> b)
        {
            if (a == null) return b;
            var r = new Dictionary<string, object>(a); foreach (var kv in b) r[kv.Key] = kv.Value; return r;
        }

        public static ExtInfo FromChromium(string browser, string profile, string id, Dictionary<string, object> s, string extDir, string temp, DateTime now)
        {
            int? loc = J.Int(s, "location");
            if (loc == 5 || loc == 10) return null;                  // a part of the browser itself (component)
            if (s != null && J.Bool(s, "was_installed_by_default") == true && J.Bool(s, "was_installed_by_oem") != true && loc == null) return null;
            Dictionary<string, object> man = J.Dict(s, "manifest"); string dir = null;
            var path = J.Str(s, "path");
            if (!string.IsNullOrEmpty(path))
            {
                var d = Path.IsPathRooted(path) ? path : Path.Combine(extDir, path);
                if (Directory.Exists(d)) { dir = d; if (man == null) man = J.Parse(FamilyProbe.ReadShared(Path.Combine(d, "manifest.json"), 1024 * 1024)); }
            }
            if (dir == null)
            {
                var idDir = Path.Combine(extDir, id);
                if (Directory.Exists(idDir))
                {
                    string[] vers; try { vers = Directory.GetDirectories(idDir); } catch { vers = new string[0]; }
                    dir = vers.Where(v => File.Exists(Path.Combine(v, "manifest.json"))).OrderByDescending(v => VersionKey(Path.GetFileName(v))).FirstOrDefault();
                    if (dir != null && man == null) man = J.Parse(FamilyProbe.ReadShared(Path.Combine(dir, "manifest.json"), 1024 * 1024));
                }
            }
            if (man == null) return null;
            if (J.Str(man, "theme") != null || J.Dict(man, "theme") != null) return null;   // a colour theme can't do anything
            var e = new ExtInfo { Browser = browser, Profile = profile, Id = id, Dir = dir, Version = J.Str(man, "version") };
            e.Name = J.Str(man, "name") ?? id;
            if (e.Name.StartsWith("__MSG_") && dir != null) e.Name = Localized(dir, J.Str(man, "default_locale") ?? "en", e.Name.Substring(6).TrimEnd('_')) ?? id;
            e.Enabled = s == null || ShieldScan.Enabled(s);
            var update = J.Str(man, "update_url") ?? "";
            bool storeUrl = StoreUpdate.Any(u => update.IndexOf(u, StringComparison.OrdinalIgnoreCase) >= 0);
            if (J.Bool(s, "from_webstore") == true || (storeUrl && (loc == null || loc == 1))) e.Source = "store";
            else if (loc == 4 || loc == 8) e.Source = "unpacked";
            else if (loc == 6 || loc == 7 || loc == 9) e.Source = "policy";
            else if (loc == 2 || loc == 3) e.Source = "sideloaded";
            else if (loc == 1 && s != null) e.Source = "store";   // "internal" = installed through the browser
            else e.Source = s == null ? (storeUrl ? "store" : "unknown") : "unknown";
            e.FromStore = e.Source == "store";
            // updated: Preferences' last_update_time (microseconds since 1601), else the folder's date
            var lut = J.Str(s, "last_update_time") ?? J.Str(s, "install_time");
            long us; if (lut != null && long.TryParse(lut, NumberStyles.Integer, CultureInfo.InvariantCulture, out us) && us > 0) try { e.Updated = DateTime.FromFileTimeUtc(us * 10).ToLocalTime(); } catch { }
            if (e.Updated == null && dir != null) try { e.Updated = Directory.GetLastWriteTime(dir); e.UpdatedFromFolder = true; } catch { }
            var perms = Strings(man, "permissions").Concat(Strings(man, "host_permissions")).ToList();
            foreach (var cs in J.List(man, "content_scripts")) perms.AddRange(Strings(cs, "matches"));
            Rate(e, perms, now);
            return e;
        }
        static string VersionKey(string v) { return string.Join(".", (v ?? "").Split('.', '_').Select(p => { int n; return int.TryParse(p, out n) ? n.ToString("D8") : p; })); }
        static IEnumerable<string> Strings(Dictionary<string, object> d, string k)
        {
            var v = J.Get(d, k) as System.Collections.IEnumerable;
            if (v == null || v is string) yield break;
            foreach (var x in v) if (x is string) yield return (string)x;
        }
        static string Localized(string dir, string locale, string key)
        {
            foreach (var loc in new[] { locale, "en", "en_US", "en_GB" })
            {
                var d = J.Parse(FamilyProbe.ReadShared(Path.Combine(dir, "_locales", loc, "messages.json"), 1024 * 1024)); if (d == null) continue;
                foreach (var kv in d) if (string.Equals(kv.Key, key, StringComparison.OrdinalIgnoreCase)) { var s = J.Str(kv.Value as Dictionary<string, object>, "message"); if (s != null) return s; }
            }
            return null;
        }

        public static bool IsAllSites(string p)
        {
            if (string.IsNullOrEmpty(p)) return false;
            return p == "<all_urls>" || p == "*://*/*" || p == "*://*/" || p == "http://*/*" || p == "https://*/*" || p == "*://*" || p == "file:///*";
        }

        // the rating. Known: Hallow Keys / Hallow Shield. Points: all sites 2, each sensitive permission 1-3, not from the store 3,
        // not updated in a year 1. High: 6+ points, or not from the store with all-sites access, or debugger with all sites.
        // Medium: 3+. Low: less.
        public static void Rate(ExtInfo e, IEnumerable<string> perms, DateTime now)
        {
            var ps = (perms ?? new string[0]).Where(x => x != null).Distinct().ToList();
            e.AllSites = ps.Any(IsAllSites); e.Sensitive.Clear(); e.Reasons.Clear();
            int pts = 0;
            if (e.AllSites) { pts += 2; e.Reasons.Add("Can read and change every website you visit."); }
            foreach (var kv in Sens)
            {
                bool has = ps.Contains(kv.Key) || (kv.Key == "declarativeNetRequest" && ps.Contains("declarativeNetRequestWithHostAccess"));
                if (!has) continue;
                if (kv.Key == "declarativeNetRequest" && !e.AllSites) continue;   // only matters together with every site
                e.Sensitive.Add(kv.Key); pts += kv.Value.Item1; e.Reasons.Add("It " + kv.Value.Item2 + ".");
            }
            if (!e.FromStore)
            {
                pts += 3;
                e.Reasons.Add(e.Source == "unpacked" ? "Not from the browser's store: loaded unpacked (developer mode)." : e.Source == "policy" ? "Not from the browser's store: added by a policy (your workplace, or a program that set one)." : e.Source == "sideloaded" ? "Not from the browser's store: added by another program (sideloaded)." : "Not from the browser's store, as far as Guard can tell.");
            }
            if (e.Updated != null && (now - e.Updated.Value).TotalDays > 365) { pts += 1; e.Reasons.Add("Not updated for over a year (" + (e.UpdatedFromFolder ? "its folder is from " : "last update ") + e.Updated.Value.ToString("MMM yyyy", CultureInfo.InvariantCulture) + ") - it may be abandoned."); }
            e.Points = pts;
            if (KnownNames.Contains(e.Name))
            {
                e.Known = true; e.Risk = "Known";
                e.Reasons.Insert(0, e.Name == "Hallow Keys" ? "A Hallow app: it fills in your passwords, so it needs every site - that broad access is expected." : "A Hallow app: it blocks ads and trackers, so it needs every site - that broad access is expected.");
                return;
            }
            if (pts >= 6 || (!e.FromStore && e.AllSites) || (e.Sensitive.Contains("debugger") && e.AllSites)) e.Risk = "High";
            else if (pts >= 3) e.Risk = "Medium";
            else { e.Risk = "Low"; if (e.Reasons.Count == 0) e.Reasons.Add("From the store, with limited access."); }
            if (!e.Enabled) e.Reasons.Add("It's switched off at the moment.");
        }

        // Firefox: extensions.json (a copy) in each profile - user-installed extensions only (not Firefox's own)
        public static List<ExtInfo> Firefox(string profiles, string temp, DateTime now)
        {
            var r = new List<ExtInfo>();
            if (string.IsNullOrEmpty(profiles) || !Directory.Exists(profiles)) return r;
            foreach (var prof in Directory.GetDirectories(profiles))
            {
                var d = J.Parse(ShieldScan.ReadCopy(Path.Combine(prof, "extensions.json"), temp, 32 * 1024 * 1024)); if (d == null) continue;
                foreach (var a in J.List(d, "addons"))
                {
                    try
                    {
                        if (J.Str(a, "type") != "extension") continue;
                        var loc = J.Str(a, "location") ?? "";
                        if (loc == "app-builtin" || loc == "app-system-defaults" || loc == "app-system-addons" || loc == "app-system-share" || loc == "app-system-local") continue;
                        var e = new ExtInfo { Browser = "Firefox", Profile = Path.GetFileName(prof), Id = J.Str(a, "id"), Version = J.Str(a, "version") };
                        e.Name = J.Str(J.Dict(a, "defaultLocale"), "name") ?? e.Id;
                        e.Enabled = J.Bool(a, "active") != false && J.Bool(a, "userDisabled") != true;
                        var src = J.Str(a, "sourceURI") ?? ""; int signed = J.Int(a, "signedState") ?? 0;
                        if (loc == "temporary-addon") e.Source = "unpacked";
                        else if (J.Bool(a, "foreignInstall") == true || loc.StartsWith("winreg") || loc == "app-system-user") e.Source = "sideloaded";
                        else if (src.IndexOf("addons.mozilla.org", StringComparison.OrdinalIgnoreCase) >= 0 || signed >= 2) e.Source = "store";
                        else e.Source = "unknown";
                        e.FromStore = e.Source == "store";
                        var up = J.Get(a, "updateDate");
                        try { if (up != null) { var ms = Convert.ToInt64(up, CultureInfo.InvariantCulture); if (ms > 0) e.Updated = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddMilliseconds(ms).ToLocalTime(); } } catch { }
                        var xpi = J.Str(a, "path"); e.Dir = xpi;
                        if (e.Updated == null && xpi != null) try { if (File.Exists(xpi)) { e.Updated = File.GetLastWriteTime(xpi); e.UpdatedFromFolder = true; } } catch { }
                        var up2 = J.Dict(a, "userPermissions");
                        var perms = Strings(up2, "permissions").Concat(Strings(up2, "origins")).ToList();
                        Rate(e, perms, now);
                        r.Add(e);
                    }
                    catch { }
                }
            }
            return r;
        }

        public static Check Evaluate(List<ExtInfo> list)
        {
            var c = new Check { Id = "extensions", Title = "Browser extensions", Group = "more", FixLabel = "Show me", FixAction = "page:extensions" };
            if (list == null) { c.State = CheckState.Unknown; c.Line = "Not looked at yet."; return c; }
            var on = list.Where(x => x.Enabled && !x.Known).ToList();
            var high = on.Where(x => x.Risk == "High").ToList(); int med = on.Count(x => x.Risk == "Medium");
            if (high.Count > 0)
            {
                c.State = CheckState.Warn; c.Penalty = Math.Min(MaxPoints, high.Count * HighPoints);
                c.Line = string.Join(", ", high.Select(x => x.Name).Distinct().Take(3)) + (high.Count > 3 ? " and " + (high.Count - 3) + " more" : "") + (high.Count == 1 ? " has" : " have") + " a lot of access to your browser and " + (high.Count == 1 ? "isn't" : "aren't") + " a usual store extension. Remove " + (high.Count == 1 ? "it" : "them") + " if you don't use " + (high.Count == 1 ? "it." : "them.");
                return c;
            }
            if (med > 0) { c.State = CheckState.Info; c.Line = med + (med == 1 ? " extension has" : " extensions have") + " broad access (common for ad blockers and password managers) - worth a look."; return c; }
            c.State = CheckState.Good; c.FixLabel = null; c.FixAction = null;
            c.Line = list.Count == 0 ? "No browser extensions found." : "No risky extensions in " + string.Join(", ", list.Select(x => x.Browser).Distinct()) + ".";
            return c;
        }

        // the browser's own extensions page - opened only when you click its button
        public static string ExtensionsUrl(string browser)
        {
            switch (browser) { case "Edge": return "edge://extensions/"; case "Brave": return "brave://extensions/"; case "Opera": case "Opera GX": return "opera://extensions"; case "Firefox": return "about:addons"; }
            return "chrome://extensions/";
        }
        public static string BrowserExe(string browser)
        {
            var exe = browser == "Edge" ? "msedge.exe" : browser == "Brave" ? "brave.exe" : browser == "Firefox" ? "firefox.exe" : browser.StartsWith("Opera") ? "opera.exe" : "chrome.exe";
            foreach (var hive in new[] { Microsoft.Win32.Registry.CurrentUser, Microsoft.Win32.Registry.LocalMachine })
                try { using (var k = hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\" + exe)) { var p = k == null ? null : k.GetValue(null) as string; if (!string.IsNullOrEmpty(p) && File.Exists(p.Trim('"'))) return p.Trim('"'); } } catch { }
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var cands = browser == "Opera GX" ? new[] { Path.Combine(local, @"Programs\Opera GX\opera.exe") } : browser == "Opera" ? new[] { Path.Combine(local, @"Programs\Opera\opera.exe") } : new string[0];
            return cands.FirstOrDefault(File.Exists);
        }
    }
}
