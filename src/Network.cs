// Hallow Guard v1.2 - the network view, read-only and offline:
//  - apps with connections right now, from Windows' own tables (GetExtendedTcpTable / GetExtendedUdpTable), grouped by program,
//    with how many hosts on the internet and on the local network. Guard sends nothing out: no country or name lookups -
//    names (reverse DNS) are looked up only when you click "Look up names".
//  - programs listening for connections from the network (not loopback), per program, with the file's signer and whether
//    Windows Firewall lets them through on private / public networks (HNetCfg.FwPolicy2, read-only).
//  - unsigned listeners running from Temp / AppData / Downloads are flagged as suspicious.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace HallowGuard
{
    public class ConnRow
    {
        public string Proto;      // TCP | UDP
        public string LocalIp, RemoteIp; public int LocalPort, RemotePort, State, Pid;   // State: TCP state (2 listen, 5 established); UDP 0
        public bool V6;
    }
    public class ProcInfo { public int Pid; public string Name, Path, Signer; }

    public class NetApp
    {
        public string Name, Path; public List<int> Pids = new List<int>();
        public int Connections, Lan;
        public List<string> Remotes = new List<string>();    // internet hosts (unique addresses)
    }
    public class FwAccess { public string Private, Public; }   // "allowed" | "blocked" | "off" (firewall off = allowed) | null (unknown)
    public class Listener
    {
        public string Name, Path, Signer; public List<int> Pids = new List<int>();
        public List<string> Ports = new List<string>();       // "TCP 445", "UDP 5353"
        public bool AllNetworks;                               // bound to every address (0.0.0.0 / ::), not one
        public FwAccess Fw; public Verdict V; public string Reason;
        public bool Exists;
    }

    public class FwRule { public string Name, App, Ports, Service; public int Protocol = 256, Profiles = 0x7FFFFFFF; public bool Allow, Enabled = true, Inbound = true; }
    public class FwFacts
    {
        public bool Read; public List<FwRule> Rules = new List<FwRule>();
        public bool?[] Enabled = new bool?[5];          // by profile type: [2] private, [4] public (index = NET_FW_PROFILE_TYPE2)
        public bool?[] DefaultAllow = new bool?[5];
    }

    public class NetSnapshot
    {
        public List<NetApp> Apps = new List<NetApp>(); public List<Listener> Listeners = new List<Listener>();
        public bool FirewallRead; public string Error; public DateTime When = DateTime.Now; public int Rows;
    }

    public static class NetTables
    {
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int cls, uint reserved);
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int af, int cls, uint reserved);
        public const int AF_INET = 2, AF_INET6 = 23, TCP_OWNER_PID_ALL = 5, UDP_OWNER_PID = 1;

        // every TCP and UDP endpoint with its process id (IPv4 and IPv6)
        public static List<ConnRow> Read()
        {
            var r = new List<ConnRow>();
            foreach (var af in new[] { AF_INET, AF_INET6 })
            {
                var b = Get(true, af); if (b != null) r.AddRange(af == AF_INET ? ParseTcp4(b) : ParseTcp6(b));
                b = Get(false, af); if (b != null) r.AddRange(af == AF_INET ? ParseUdp4(b) : ParseUdp6(b));
            }
            return r;
        }
        static byte[] Get(bool tcp, int af)
        {
            int size = 0;
            for (int i = 0; i < 4; i++)
            {
                var p = size > 0 ? Marshal.AllocHGlobal(size) : IntPtr.Zero;
                try
                {
                    uint rc = tcp ? GetExtendedTcpTable(p, ref size, false, af, TCP_OWNER_PID_ALL, 0) : GetExtendedUdpTable(p, ref size, false, af, UDP_OWNER_PID, 0);
                    if (rc == 0 && p != IntPtr.Zero) { var b = new byte[size]; Marshal.Copy(p, b, 0, size); return b; }
                    if (rc != 122) return null;   // ERROR_INSUFFICIENT_BUFFER: try again with the size Windows asked for
                    size += 4096;
                }
                finally { if (p != IntPtr.Zero) Marshal.FreeHGlobal(p); }
            }
            return null;
        }
        static uint U32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
        // ports are in network byte order in the low 16 bits
        public static int Port(uint v) { return (int)(((v & 0xFF) << 8) | ((v >> 8) & 0xFF)); }
        static string V4(uint v) { return new IPAddress(v).ToString(); }
        static string V6(byte[] b, int o) { var a = new byte[16]; Array.Copy(b, o, a, 0, 16); return new IPAddress(a).ToString(); }
        static int Count(byte[] b, int rowSize) { if (b == null || b.Length < 4) return 0; var n = (int)Math.Min(U32(b, 0), (uint)((b.Length - 4) / rowSize)); return n; }

        // MIB_TCPTABLE_OWNER_PID: count, then rows of { state, localAddr, localPort, remoteAddr, remotePort, pid } (6 x 4 bytes)
        public static List<ConnRow> ParseTcp4(byte[] b)
        {
            var r = new List<ConnRow>(); int n = Count(b, 24);
            for (int i = 0; i < n; i++) { int o = 4 + i * 24; r.Add(new ConnRow { Proto = "TCP", State = (int)U32(b, o), LocalIp = V4(U32(b, o + 4)), LocalPort = Port(U32(b, o + 8)), RemoteIp = V4(U32(b, o + 12)), RemotePort = Port(U32(b, o + 16)), Pid = (int)U32(b, o + 20) }); }
            return r;
        }
        // MIB_TCP6TABLE_OWNER_PID rows: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid (56 bytes)
        public static List<ConnRow> ParseTcp6(byte[] b)
        {
            var r = new List<ConnRow>(); int n = Count(b, 56);
            for (int i = 0; i < n; i++) { int o = 4 + i * 56; r.Add(new ConnRow { Proto = "TCP", V6 = true, LocalIp = V6(b, o), LocalPort = Port(U32(b, o + 20)), RemoteIp = V6(b, o + 24), RemotePort = Port(U32(b, o + 44)), State = (int)U32(b, o + 48), Pid = (int)U32(b, o + 52) }); }
            return r;
        }
        // MIB_UDPTABLE_OWNER_PID rows: localAddr, localPort, pid (12 bytes)
        public static List<ConnRow> ParseUdp4(byte[] b)
        {
            var r = new List<ConnRow>(); int n = Count(b, 12);
            for (int i = 0; i < n; i++) { int o = 4 + i * 12; r.Add(new ConnRow { Proto = "UDP", LocalIp = V4(U32(b, o)), LocalPort = Port(U32(b, o + 4)), Pid = (int)U32(b, o + 8) }); }
            return r;
        }
        // MIB_UDP6TABLE_OWNER_PID rows: localAddr[16], localScope, localPort, pid (28 bytes)
        public static List<ConnRow> ParseUdp6(byte[] b)
        {
            var r = new List<ConnRow>(); int n = Count(b, 28);
            for (int i = 0; i < n; i++) { int o = 4 + i * 28; r.Add(new ConnRow { Proto = "UDP", V6 = true, LocalIp = V6(b, o), LocalPort = Port(U32(b, o + 20)), Pid = (int)U32(b, o + 24) }); }
            return r;
        }
    }

    public static class NetView
    {
        public const int SuspiciousPoints = 6;
        static IPAddress Ip(string s) { IPAddress a; return IPAddress.TryParse((s ?? "").Split('%')[0], out a) ? a : null; }
        public static bool IsLoopback(string s) { var a = Ip(s); return a != null && IPAddress.IsLoopback(a); }
        public static bool IsAny(string s) { var a = Ip(s); return a != null && (a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)); }
        // private / link-local / unique-local addresses: the local network, not the internet
        public static bool IsLan(string s)
        {
            var a = Ip(s); if (a == null) return false;
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            var b = a.GetAddressBytes();
            if (b.Length == 4) return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC;
        }
        static string Key(ProcInfo p) { return !string.IsNullOrEmpty(p.Path) ? p.Path.ToLowerInvariant() : "name:" + (p.Name ?? "?").ToLowerInvariant() + (p.Name == null ? ":" + p.Pid : ""); }

        // established TCP connections to anything but this PC, grouped by program
        public static List<NetApp> Apps(IEnumerable<ConnRow> rows, Func<int, ProcInfo> proc)
        {
            var by = new Dictionary<string, NetApp>();
            foreach (var r in rows)
            {
                if (r.Proto != "TCP" || r.State != 5 || IsLoopback(r.RemoteIp) || IsAny(r.RemoteIp)) continue;
                var p = proc(r.Pid) ?? new ProcInfo { Pid = r.Pid }; var k = Key(p);
                NetApp a; if (!by.TryGetValue(k, out a)) by[k] = a = new NetApp { Name = DisplayName(p), Path = p.Path };
                if (!a.Pids.Contains(r.Pid)) a.Pids.Add(r.Pid);
                a.Connections++;
                var remote = (r.RemoteIp ?? "").Split('%')[0]; var ip = Ip(remote); if (ip != null && ip.IsIPv4MappedToIPv6) remote = ip.MapToIPv4().ToString();
                if (IsLan(remote)) a.Lan++;
                else if (!a.Remotes.Contains(remote)) a.Remotes.Add(remote);
            }
            return by.Values.OrderByDescending(a => a.Remotes.Count).ThenByDescending(a => a.Connections).ThenBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
        public static string DisplayName(ProcInfo p)
        {
            if (p.Pid == 4) return "System (Windows)";
            if (p.Pid == 0) return "Windows";
            if (!string.IsNullOrEmpty(p.Name)) return p.Name;
            if (!string.IsNullOrEmpty(p.Path)) return Path.GetFileNameWithoutExtension(p.Path);
            return "process " + p.Pid;
        }

        // TCP listening sockets and UDP sockets that aren't bound to loopback, grouped by program
        public static List<Listener> Listeners(IEnumerable<ConnRow> rows, Func<int, ProcInfo> proc, FwFacts fw, PathRoots roots, Func<string, bool> exists)
        {
            var by = new Dictionary<string, Listener>(); var ports = new Dictionary<string, List<Tuple<string, int>>>();
            foreach (var r in rows)
            {
                bool listening = r.Proto == "TCP" ? r.State == 2 : r.Proto == "UDP";
                if (!listening || IsLoopback(r.LocalIp)) continue;
                var p = proc(r.Pid) ?? new ProcInfo { Pid = r.Pid }; var k = Key(p);
                Listener l; if (!by.TryGetValue(k, out l)) { by[k] = l = new Listener { Name = DisplayName(p), Path = p.Path, Signer = p.Signer }; ports[k] = new List<Tuple<string, int>>(); }
                if (!l.Pids.Contains(r.Pid)) l.Pids.Add(r.Pid);
                if (IsAny(r.LocalIp)) l.AllNetworks = true;
                var t = Tuple.Create(r.Proto, r.LocalPort); if (!ports[k].Contains(t)) ports[k].Add(t);
            }
            foreach (var kv in by)
            {
                var l = kv.Value; var ps = ports[kv.Key].OrderBy(x => x.Item1 == "TCP" ? 0 : 1).ThenBy(x => x.Item2).ToList();
                l.Ports = ps.Select(x => x.Item1 + " " + x.Item2).ToList();
                l.Exists = l.Path != null && exists(l.Path);
                l.Fw = Firewall(l.Path, l.Pids.Contains(4), ps, fw);
                string reason; l.V = Classify(l, roots, out reason); l.Reason = reason;
            }
            return by.Values.OrderBy(x => x.V == Verdict.Suspicious ? 0 : x.V == Verdict.Unknown ? 1 : 2).ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static Verdict Classify(Listener l, PathRoots roots, out string reason)
        {
            if (l.Pids.Contains(4) || l.Pids.Contains(0)) { reason = "Windows itself (file and printer sharing, network discovery and similar)."; return Verdict.KnownGood; }
            if (string.IsNullOrEmpty(l.Path)) { reason = "Windows didn't say which program this is - usually a protected Windows service."; return Verdict.Unknown; }
            if (Classifier.IsHallow(l.Path, roots)) { reason = "A Hallow app."; return Verdict.KnownGood; }
            if (!string.IsNullOrEmpty(l.Signer))
            {
                if (Classifier.IsWellKnown(l.Signer)) { reason = "Signed by " + l.Signer + "."; return Verdict.KnownGood; }
                reason = "Signed by " + l.Signer + " - check you recognise it."; return Verdict.Unknown;
            }
            var place = Classifier.RiskyPlace(l.Path, roots);
            if (place == null && !string.IsNullOrEmpty(roots.Windows) && l.Path.StartsWith(roots.Windows.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)) { reason = "Part of Windows (in the Windows folder)."; return Verdict.KnownGood; }
            if (place != null) { reason = "Not signed and runs from " + place + ", but waits for connections from the network - malware often looks like this."; return Verdict.Suspicious; }
            reason = "Not signed - check you recognise it."; return Verdict.Unknown;
        }

        // ---- Windows Firewall: is a program's port let in on private / public networks?
        public static bool PortMatches(string ports, int port)
        {
            if (string.IsNullOrEmpty(ports) || ports == "*" || ports.Equals("Any", StringComparison.OrdinalIgnoreCase)) return true;
            foreach (var part in ports.Split(','))
            {
                var s = part.Trim(); int a, b; var dash = s.IndexOf('-');
                if (dash > 0 && int.TryParse(s.Substring(0, dash), out a) && int.TryParse(s.Substring(dash + 1), out b)) { if (port >= a && port <= b) return true; }
                else if (int.TryParse(s, out a) && a == port) return true;
            }
            return false;
        }
        static bool AnyPorts(string ports) { return string.IsNullOrEmpty(ports) || ports == "*" || ports.Equals("Any", StringComparison.OrdinalIgnoreCase); }
        static bool AppMatches(FwRule r, string path, bool system)
        {
            if (string.IsNullOrEmpty(r.App) || r.App == "*") return !AnyPorts(r.Ports);   // a port rule for any program (a rule for every program and port is too broad to say)
            if (system) return r.App.Equals("System", StringComparison.OrdinalIgnoreCase);
            if (path == null) return false;
            return string.Equals(Environment.ExpandEnvironmentVariables(r.App).Trim('"'), path, StringComparison.OrdinalIgnoreCase);
        }
        public static FwAccess Firewall(string path, bool system, List<Tuple<string, int>> ports, FwFacts fw)
        {
            if (fw == null || !fw.Read) return new FwAccess();
            Func<int, string> one = prof =>
            {
                if (fw.Enabled[prof] == false) return "off";
                bool anyAllowed = false;
                foreach (var pt in ports)
                {
                    int proto = pt.Item1 == "TCP" ? 6 : 17;
                    var rules = fw.Rules.Where(r => r.Enabled && r.Inbound && (r.Profiles & prof) != 0 && (r.Protocol == 256 || r.Protocol == proto) && AppMatches(r, path, system) && PortMatches(r.Ports, pt.Item2)).ToList();
                    if (rules.Any(r => !r.Allow)) continue;                   // a block rule wins
                    if (rules.Any(r => r.Allow) || fw.DefaultAllow[prof] == true) { anyAllowed = true; break; }
                }
                return anyAllowed ? "allowed" : fw.Enabled[prof] == null && fw.DefaultAllow[prof] == null ? null : "blocked";
            };
            return new FwAccess { Private = one(2), Public = one(4) };
        }
        public static string FirewallText(FwAccess f)
        {
            if (f == null || (f.Private == null && f.Public == null)) return "Firewall: couldn't read.";
            Func<string, bool> open = s => s == "allowed" || s == "off";
            bool pr = open(f.Private), pu = open(f.Public);
            string off = f.Private == "off" || f.Public == "off" ? " (Windows Firewall is off there)" : "";
            if (pr && pu) return "Firewall: let in on private and public networks" + off + ".";
            if (pr) return "Firewall: let in on private (home) networks, blocked on public ones" + off + ".";
            if (pu) return "Firewall: let in on public networks, blocked on private ones" + off + ".";
            return "Firewall: blocked - other devices can't reach it.";
        }

        public static Check Evaluate(NetSnapshot n)
        {
            var c = new Check { Id = "listeners", Title = "Programs open to the network", Group = "more", FixLabel = "Show me", FixAction = "page:network" };
            if (n == null) { c.State = CheckState.Unknown; c.Line = "Not looked at yet."; return c; }
            if (n.Error != null) { c.State = CheckState.Unknown; c.Line = "Couldn't read the connection tables: " + n.Error; return c; }
            var bad = n.Listeners.Where(l => l.V == Verdict.Suspicious).ToList();
            if (bad.Count > 0) { c.State = CheckState.Bad; c.Penalty = SuspiciousPoints; c.Line = string.Join(", ", bad.Select(l => l.Name).Take(3)) + (bad.Count > 3 ? " and " + (bad.Count - 3) + " more" : "") + (bad.Count == 1 ? " isn't signed, runs from " : " aren't signed, run from ") + "Temp or AppData and " + (bad.Count == 1 ? "waits" : "wait") + " for connections from the network. Scan " + (bad.Count == 1 ? "it" : "them") + " with Defender."; return c; }
            var unknown = n.Listeners.Count(l => l.V == Verdict.Unknown);
            c.State = CheckState.Good; c.FixLabel = null; c.FixAction = null;
            c.Line = n.Listeners.Count == 0 ? "Nothing on this PC is waiting for connections from the network." : n.Listeners.Count + (n.Listeners.Count == 1 ? " program waits" : " programs wait") + " for connections from the network; none look suspicious." + (unknown > 0 ? " " + unknown + " aren't from a publisher Guard knows - the Network page shows them." : "");
            return c;
        }
    }

    public interface INetSource { NetSnapshot Read(); }

    // the real PC: the connection tables, process paths and signers, and the firewall rules (all read-only)
    public class WindowsNet : INetSource
    {
        readonly PathRoots roots = PathRoots.Current();
        public NetSnapshot Read()
        {
            var s = new NetSnapshot();
            List<ConnRow> rows;
            try { rows = NetTables.Read(); } catch (Exception e) { s.Error = e.Message; return s; }
            s.Rows = rows.Count;
            var procs = new Dictionary<int, ProcInfo>(); var signFor = new HashSet<int>();
            foreach (var r in rows) if ((r.Proto == "TCP" && r.State == 2) || r.Proto == "UDP") if (!NetView.IsLoopback(r.LocalIp)) signFor.Add(r.Pid);
            Func<int, ProcInfo> proc = pid =>
            {
                ProcInfo p; if (procs.TryGetValue(pid, out p)) return p;
                p = new ProcInfo { Pid = pid };
                if (pid > 4)
                {
                    try { using (var pr = Process.GetProcessById(pid)) p.Name = pr.ProcessName; } catch { }
                    try { p.Path = WindowsLeftovers.ProcessPath(pid); } catch { }
                    if (p.Path != null && signFor.Contains(pid)) p.Signer = Signing.Signer(p.Path);
                }
                procs[pid] = p; return p;
            };
            var fw = ReadFirewall(); s.FirewallRead = fw.Read;
            s.Apps = NetView.Apps(rows, proc);
            s.Listeners = NetView.Listeners(rows, proc, fw, roots, File.Exists);
            return s;
        }
        static object Get(object o, string p, params object[] a) { return o.GetType().InvokeMember(p, BindingFlags.GetProperty, null, o, a.Length == 0 ? null : a); }
        public static FwFacts ReadFirewall()
        {
            var f = new FwFacts();
            object pol = null;
            try
            {
                var t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2"); if (t == null) return f;
                pol = Activator.CreateInstance(t);
                foreach (var prof in new[] { 2, 4 })
                {
                    try { f.Enabled[prof] = Convert.ToBoolean(Get(pol, "FirewallEnabled", prof)); } catch { }
                    try { f.DefaultAllow[prof] = Convert.ToInt32(Get(pol, "DefaultInboundAction", prof)) == 1; } catch { }
                }
                var rules = Get(pol, "Rules") as System.Collections.IEnumerable;
                if (rules != null)
                    foreach (var r in rules)
                    {
                        try
                        {
                            if (Convert.ToInt32(Get(r, "Direction")) != 1) continue;   // inbound only
                            f.Rules.Add(new FwRule
                            {
                                Name = Get(r, "Name") as string, App = Get(r, "ApplicationName") as string, Ports = Get(r, "LocalPorts") as string, Service = Get(r, "ServiceName") as string,
                                Protocol = Convert.ToInt32(Get(r, "Protocol")), Profiles = Convert.ToInt32(Get(r, "Profiles")), Allow = Convert.ToInt32(Get(r, "Action")) == 1, Enabled = Convert.ToBoolean(Get(r, "Enabled")), Inbound = true
                            });
                        }
                        catch { }
                        finally { try { Marshal.ReleaseComObject(r); } catch { } }
                    }
                f.Read = true;
            }
            catch { }
            finally { if (pol != null) try { Marshal.FinalReleaseComObject(pol); } catch { } }
            return f;
        }

        // reverse DNS for addresses - only when you click "Look up names" (each takes at most a few seconds)
        public static Dictionary<string, string> LookUpNames(IEnumerable<string> ips, int max = 80)
        {
            var r = new Dictionary<string, string>(); var list = ips.Distinct().Take(max).ToList();
            var tasks = list.Select(ip => new { ip, ar = Dns.BeginGetHostEntry(ip, null, null) }).ToList();
            var until = DateTime.Now.AddSeconds(6);
            foreach (var t in tasks)
            {
                var left = until - DateTime.Now;
                if (left > TimeSpan.Zero && t.ar.AsyncWaitHandle.WaitOne(left))
                    try { var h = Dns.EndGetHostEntry(t.ar); if (!string.IsNullOrEmpty(h.HostName) && h.HostName != t.ip) r[t.ip] = h.HostName; } catch { }
            }
            return r;
        }
    }
}
