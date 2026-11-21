// Hallow Guard - VirusTotal second opinion (optional). With your own free API key (Settings, kept DPAPI-encrypted) a lookup
// sends ONLY the file's SHA-256: GET /api/v3/files/{sha256}. Files are never uploaded. Without a key, "Look up" opens
// https://www.virustotal.com/gui/file/<sha256> in your browser instead.
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace HallowGuard
{
    public class VtResult
    {
        public bool Found; public int Malicious, Suspicious, Harmless, Undetected; public string Name, Error;
        public string Summary
        {
            get
            {
                if (Error != null) return Error;
                if (!Found) return "VirusTotal hasn't seen this file before - that alone doesn't mean it's bad, just uncommon.";
                int total = Malicious + Suspicious + Harmless + Undetected;
                if (Malicious == 0 && Suspicious == 0) return "VirusTotal: no engine flags this file (" + total + " checked).";
                return "VirusTotal: " + Malicious + " of " + total + " engines flag this file" + (Suspicious > 0 ? " (" + Suspicious + " more call it suspicious)" : "") + ". A handful of flags is often a false alarm; many is a real warning.";
            }
        }
    }

    public class VtClient
    {
        public const string DefaultBase = "https://www.virustotal.com";
        readonly string key, baseUrl;
        public VtClient(string apiKey, string baseUrl = null) { key = apiKey; this.baseUrl = (baseUrl ?? DefaultBase).TrimEnd('/'); }

        public static bool IsSha256(string h) { return h != null && Regex.IsMatch(h, "^[0-9a-fA-F]{64}$"); }
        public static string GuiUrl(string sha256) { if (!IsSha256(sha256)) throw new ArgumentException("not a SHA-256"); return "https://www.virustotal.com/gui/file/" + sha256.ToLowerInvariant(); }
        public static string Sha256File(string path)
        {
            using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) using (var sha = SHA256.Create())
                return BitConverter.ToString(sha.ComputeHash(f)).Replace("-", "").ToLowerInvariant();
        }

        // the one request a lookup makes: a GET with the hash in the path and the key in a header - no body, nothing else
        public HttpWebRequest Build(string sha256)
        {
            if (!IsSha256(sha256)) throw new ArgumentException("not a SHA-256");
            if (string.IsNullOrEmpty(key)) throw new InvalidOperationException("no API key");
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var req = (HttpWebRequest)WebRequest.Create(baseUrl + "/api/v3/files/" + sha256.ToLowerInvariant());
            req.Method = "GET"; req.Accept = "application/json"; req.UserAgent = "HallowGuard/" + Program.Version;
            req.Headers["x-apikey"] = key; req.Timeout = 20000; req.ReadWriteTimeout = 20000; req.AllowAutoRedirect = false;
            return req;
        }

        public VtResult Lookup(string sha256)
        {
            try
            {
                var req = Build(sha256);
                using (var resp = (HttpWebResponse)req.GetResponse()) using (var r = new StreamReader(resp.GetResponseStream())) return Parse(r.ReadToEnd());
            }
            catch (WebException e)
            {
                var hr = e.Response as HttpWebResponse; var code = hr == null ? 0 : (int)hr.StatusCode;
                if (code == 404) return new VtResult { Found = false };
                if (code == 401) return new VtResult { Error = "VirusTotal didn't accept the API key - check it in Settings." };
                if (code == 429) return new VtResult { Error = "VirusTotal says too many lookups for now (the free key allows 4 a minute). Try again shortly." };
                return new VtResult { Error = "Couldn't reach VirusTotal: " + e.Message };
            }
            catch (Exception e) { return new VtResult { Error = "VirusTotal lookup failed: " + e.Message }; }
        }
        public static VtResult Parse(string json)
        {
            var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json);
            var data = Obj(d, "data"); var attr = Obj(data, "attributes"); var st = Obj(attr, "last_analysis_stats");
            if (st == null) return new VtResult { Error = "VirusTotal answered something unexpected." };
            object n; var res = new VtResult { Found = true, Malicious = Int(st, "malicious"), Suspicious = Int(st, "suspicious"), Harmless = Int(st, "harmless"), Undetected = Int(st, "undetected") };
            if (attr != null && attr.TryGetValue("meaningful_name", out n)) res.Name = n as string;
            return res;
        }
        static Dictionary<string, object> Obj(Dictionary<string, object> d, string k) { object v; return d != null && d.TryGetValue(k, out v) ? v as Dictionary<string, object> : null; }
        static int Int(Dictionary<string, object> d, string k) { object v; try { return d.TryGetValue(k, out v) && v != null ? Convert.ToInt32(v) : 0; } catch { return 0; } }
    }
}
