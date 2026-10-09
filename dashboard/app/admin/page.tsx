"use client";
import { useEffect, useState, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  Shield, Activity, AlertTriangle, Users,
  LogOut, User, BarChart3, Trash2,
  RefreshCw, ClipboardList, UserPlus, CheckCircle, XCircle, X, Bell,
  Upload, Radio
} from "lucide-react";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

import { API, wsUrl } from "@/lib/api";
const COLORS = ["#ef4444","#f97316","#eab308","#22c55e","#06b6d4","#8b5cf6"];

interface Me { user_id: number; username: string; role: string; email: string; department: string }
type Row = Record<string, string | number | boolean | null>;

const badge = (s: string) => {
  const c: Record<string,string> = {
    Critical:"bg-red-900 text-red-300", High:"bg-orange-900 text-orange-300",
    Medium:"bg-yellow-900 text-yellow-300", Low:"bg-green-900 text-green-300",
  };
  return <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${c[s] ?? "bg-gray-700 text-gray-300"}`}>{s}</span>;
};

const TABS = [
  { id:"overview",  label:"Overview",      icon: BarChart3,    link: null },
  { id:"iocs",      label:"IOC Manager",   icon: Activity,     link: null },
  { id:"actors",    label:"Actors",        icon: Users,        link: null },
  { id:"incidents", label:"Incidents",     icon: AlertTriangle,link: null },
  { id:"audit",     label:"Audit Log",     icon: ClipboardList,link: null },
  { id:"users",     label:"Users",         icon: User,         link: null },
  { id:"pcap",      label:"PCAP Analysis", icon: Upload,       link: "/upload" },
  { id:"capture",   label:"Live Capture",  icon: Radio,        link: "/capture" },
];

export default function AdminPage() {
  const router = useRouter();
  const [me,        setMe]        = useState<Me | null>(null);
  const [tab,       setTab]       = useState("overview");
  const [stats,     setStats]     = useState<Row | null>(null);
  const [pie,       setPie]       = useState<{name:string;value:number}[]>([]);
  const [bar,       setBar]       = useState<{name:string;value:number}[]>([]);
  const [iocs,      setIocs]      = useState<Row[]>([]);
  const [actors,    setActors]    = useState<Row[]>([]);
  const [incidents, setIncidents] = useState<Row[]>([]);
  const [audit,     setAudit]     = useState<Row[]>([]);
  const [users,     setUsers]     = useState<Row[]>([]);
  const [loading,   setLoading]   = useState(true);
  const [newUser,   setNewUser]   = useState({ username:"", password:"", email:"", department:"Threat Intelligence" });
  const [createMsg, setCreateMsg] = useState("");

  // ── Notification system ──────────────────────────────────────────────
  interface Notif {
    id: string; type: string; value: string; severity: string;
    confidence: number; context: string; submitted_by: string; timestamp: string;
  }
  const [notifs,  setNotifs]  = useState<Notif[]>([]);
  const wsNotif   = useRef<WebSocket | null>(null);
  const pingTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  // Auth check
  useEffect(() => {
    const raw = localStorage.getItem("ctims_user");
    if (!raw) { router.push("/login"); return; }
    const u = JSON.parse(raw) as Me;
    if (u.role.toLowerCase() !== "admin") { router.push("/analyst"); return; }
    setMe(u);
  }, [router]);

  const safeFetch = async (url: string) => {
    try { const r = await fetch(url); return r.ok ? r.json() : null; }
    catch { return null; }
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, i, a, inc, aud] = await Promise.all([
        safeFetch(`${API}/api/stats`),
        safeFetch(`${API}/api/indicators`),
        safeFetch(`${API}/api/actors`),
        safeFetch(`${API}/api/incidents`),
        safeFetch(`${API}/api/audit`),
      ]);
      if (s) {
        setStats(s.dashboard);
        setPie((s.typeBreakdown as Row[]).map((r: Row) => ({ name: String(r.name), value: Number(r.value) })));
        setBar((s.actorActivity as Row[]).map((r: Row) => ({ name: String(r.name), value: Number(r.value) })));
      }
      if (Array.isArray(i)) setIocs(i);
      if (Array.isArray(a)) setActors(a);
      if (Array.isArray(inc)) setIncidents(inc);
      if (Array.isArray(aud)) setAudit(aud);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadUsers = useCallback(async () => {
    try {
      const r = await fetch(`${API}/api/users`);
      if (r.ok) setUsers(await r.json());
    } catch { setUsers([]); }
  }, []);

  const createAnalyst = async () => {
    if (!newUser.username || !newUser.password) return;
    setCreateMsg("Creating…");
    try {
      const res = await fetch(`${API}/api/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...newUser, role: "analyst" }),
      });
      const d = await res.json();
      if (d.success) {
        setCreateMsg(`✓ Analyst '${newUser.username}' created (ID #${d.user_id})`);
        setNewUser({ username:"", password:"", email:"", department:"Threat Intelligence" });
        loadUsers();
      } else {
        setCreateMsg(`✗ ${d.detail ?? d.error}`);
      }
    } catch {
      setCreateMsg("✗ Server error");
    }
  };

  useEffect(() => {
    if (me) { load(); loadUsers(); }
  }, [me, load, loadUsers]);

  // Connect WebSocket for live analyst notifications
  useEffect(() => {
    if (!me) return;

    const connect = () => {
      const ws = new WebSocket(wsUrl("/ws/live"));
      wsNotif.current = ws;

      ws.onopen = () => {
        pingTimer.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send("ping");
        }, 25000);
      };

      ws.onmessage = (e) => {
        try {
          const { event, data } = JSON.parse(e.data);
          if (event === "new_indicator") {
            const notif: Notif = {
              id:           `${Date.now()}-${Math.random()}`,
              type:         data.type,
              value:        data.value,
              severity:     data.severity,
              confidence:   data.confidence ?? 70,
              context:      data.context ?? "",
              submitted_by: data.submitted_by ?? "analyst",
              timestamp:    data.timestamp ?? new Date().toLocaleTimeString(),
            };
            setNotifs(prev => [notif, ...prev].slice(0, 8));
            // Auto-dismiss after 12 seconds
            setTimeout(() => dismissNotif(notif.id), 12000);
          }
        } catch { /* ignore */ }
      };

      ws.onclose = () => {
        if (pingTimer.current) clearInterval(pingTimer.current);
        setTimeout(connect, 3000);
      };
      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      if (pingTimer.current) clearInterval(pingTimer.current);
      wsNotif.current?.close();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me]);

  const dismissNotif = (id: string) => setNotifs(prev => prev.filter(n => n.id !== id));

  const logout = () => { localStorage.removeItem("ctims_user"); router.push("/login"); };

  const deleteIOC = async (id: number) => {
    if (!confirm("Delete this indicator?")) return;
    const res = await fetch(`${API}/api/indicators/${id}`, { method: "DELETE" });
    if (res.ok) {
      setIocs(prev => prev.filter(r => r.indicator_id !== id));
    } else {
      const d = await res.json().catch(() => ({}));
      alert(d.detail ?? "Cannot delete this indicator.");
    }
  };

  if (!me || loading) return (
    <div className="min-h-screen flex items-center justify-center text-cyan-400 animate-pulse text-lg"
      style={{ background: "#0b0e14" }}>
      Loading Admin Dashboard…
    </div>
  );

  return (
    <div className="min-h-screen" style={{ background: "#0b0e14" }}>
      {/* Top nav */}
      <header className="flex items-center justify-between px-6 py-4 border-b"
        style={{ background: "#0d1117", borderColor: "#1e2a3a" }}>
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg" style={{ background: "#1e2a3a", boxShadow: "0 0 12px rgba(101,163,13,0.4)" }}>
            <Shield size={20} style={{ color: "#65a30d" }} />
          </div>
          <div>
            <span className="font-bold tracking-widest text-sm" style={{ color: "#65a30d" }}>CTIMS</span>
            <span className="text-gray-600 text-xs ml-3">Admin Dashboard</span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-2 text-sm text-gray-300">
            <div className="w-7 h-7 rounded-full bg-lime-900 flex items-center justify-center">
              <User size={14} style={{ color: "#65a30d" }} />
            </div>
            {me.email ? me.email.split("@")[0] : me.username}
            <span className="text-xs bg-lime-900/40 border border-lime-800 text-lime-400 px-2 py-0.5 rounded-full capitalize">{me.role}</span>
          </span>
          {/* Notification bell */}
          <div className="relative">
            <button className="text-gray-500 hover:text-gray-300 p-1.5 rounded-lg hover:bg-gray-800 transition-colors">
              <Bell size={16} />
            </button>
            {notifs.length > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center font-bold">
                {notifs.length}
              </span>
            )}
          </div>
          <button onClick={() => load()}
            className="text-gray-500 hover:text-gray-300 transition-colors p-1.5 rounded-lg hover:bg-gray-800">
            <RefreshCw size={15} />
          </button>
          <button onClick={logout}
            className="flex items-center gap-2 bg-red-900/30 hover:bg-red-800/60 border border-red-800 text-red-400 hover:text-red-300 text-sm px-3 py-1.5 rounded-lg transition-all font-medium">
            <LogOut size={15} /> Sign Out
          </button>
        </div>
      </header>

      <div className="flex">
        {/* Side tabs */}
        <aside className="w-48 shrink-0 min-h-screen p-3 space-y-1 border-r"
          style={{ background: "#0b0e14", borderColor: "#1e2a3a" }}>
          {TABS.map(({ id, label, icon: Icon, link }) => (
            <button key={id}
              onClick={() => link ? router.push(link) : setTab(id)}
              className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm transition-all text-left"
              style={!link && tab === id
                ? { background: "rgba(101,163,13,0.15)", color: "#84cc16", border: "1px solid rgba(101,163,13,0.3)" }
                : link
                  ? { color: "#06b6d4", border: "1px solid transparent" }
                  : { color: "#6b7280", border: "1px solid transparent" }}>
              <Icon size={14} />
              {label}
              {link && <span className="ml-auto text-xs opacity-50">↗</span>}
            </button>
          ))}
          <div className="pt-4 border-t mt-4" style={{ borderColor: "#1e2a3a" }}>
            <p className="text-xs text-gray-600 px-2">Indicators: <span className="text-cyan-400">{iocs.length}</span></p>
            <p className="text-xs text-gray-600 px-2 mt-1">Alerts: <span className="text-red-400">{incidents.length}</span></p>
            <button
              onClick={() => setTab("users")}
              className="mt-3 w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold transition-all"
              style={{ background: "rgba(6,182,212,0.12)", color: "#06b6d4", border: "1px solid rgba(6,182,212,0.25)" }}>
              <UserPlus size={13} /> Create Analyst
            </button>
            <button
              onClick={logout}
              className="mt-2 w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all"
              style={{ background: "rgba(239,68,68,0.1)", color: "#f87171", border: "1px solid rgba(239,68,68,0.2)" }}>
              <LogOut size={13} /> Sign Out
            </button>
          </div>
        </aside>

        {/* Main content */}
        <main className="flex-1 p-6">

          {/* ── OVERVIEW ─────────────────────────────── */}
          {tab === "overview" && (
            <div className="space-y-6">
              <h2 className="text-xl font-bold text-gray-200">System Overview</h2>
              <div className="grid grid-cols-3 gap-4">
                {[
                  { label:"Active Indicators",  val: stats?.active_indicators   ?? 0, color:"text-cyan-400",   bg:"border-cyan-800 bg-cyan-900/10" },
                  { label:"Critical IOCs",       val: stats?.critical_indicators  ?? 0, color:"text-red-400",    bg:"border-red-800 bg-red-900/10" },
                  { label:"Open Incidents",      val: stats?.open_incidents       ?? 0, color:"text-orange-400", bg:"border-orange-800 bg-orange-900/10" },
                  { label:"Threat Actors",       val: stats?.active_actors        ?? 0, color:"text-purple-400", bg:"border-purple-800 bg-purple-900/10" },
                  { label:"Unpatched Vulns",     val: stats?.unpatched_vulns      ?? 0, color:"text-yellow-400", bg:"border-yellow-800 bg-yellow-900/10" },
                  { label:"Malware Entries",     val: stats?.total_malware        ?? 0, color:"text-blue-400",   bg:"border-blue-800 bg-blue-900/10" },
                ].map(({ label, val, color, bg }) => (
                  <div key={label} className={`border rounded-xl p-5 ${bg}`}>
                    <p className="text-gray-400 text-xs uppercase tracking-wider">{label}</p>
                    <p className={`text-3xl font-bold mt-1 ${color}`}>{val}</p>
                  </div>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
                  <h3 className="text-sm font-bold text-gray-300 mb-4 uppercase tracking-wider">IOC Type Breakdown</h3>
                  {pie.length > 0 ? (
                    <ResponsiveContainer width="100%" height={180}>
                      <PieChart>
                        <Pie data={pie} cx="50%" cy="50%" outerRadius={70} dataKey="value"
                          label={({ name, percent }) => `${name} ${((percent??0)*100).toFixed(0)}%`} labelLine={false}>
                          {pie.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                        </Pie>
                        <Tooltip contentStyle={{ background:"#1f2937", border:"1px solid #374151", color:"#e5e7eb" }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : <p className="text-gray-600 text-sm text-center py-12">No data</p>}
                </div>
                <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
                  <h3 className="text-sm font-bold text-gray-300 mb-4 uppercase tracking-wider">Top Threat Actors</h3>
                  {bar.length > 0 ? (
                    <ResponsiveContainer width="100%" height={180}>
                      <BarChart data={bar} margin={{ left:-10 }}>
                        <XAxis dataKey="name" tick={{ fill:"#9ca3af", fontSize:9 }} />
                        <YAxis tick={{ fill:"#9ca3af", fontSize:10 }} />
                        <Tooltip contentStyle={{ background:"#1f2937", border:"1px solid #374151", color:"#e5e7eb" }} />
                        <Bar dataKey="value" fill="#65a30d" radius={[4,4,0,0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : <p className="text-gray-600 text-sm text-center py-12">No data</p>}
                </div>
              </div>
            </div>
          )}

          {/* ── IOC MANAGER ──────────────────────────── */}
          {tab === "iocs" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold text-gray-200">IOC Manager</h2>
                <span className="text-sm text-gray-500">{iocs.length} indicators total</span>
              </div>
              <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                      <th className="text-left px-4 py-3">ID</th>
                      <th className="text-left px-4 py-3">Type</th>
                      <th className="text-left px-4 py-3">Value</th>
                      <th className="text-left px-4 py-3">Severity</th>
                      <th className="text-left px-4 py-3">Confidence</th>
                      <th className="text-left px-4 py-3">Actor</th>
                      <th className="text-left px-4 py-3">Status</th>
                      <th className="px-4 py-3"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.length === 0 ? (
                      <tr><td colSpan={8} className="text-center text-gray-600 py-10">No indicators. Add some via the Java CLI or PCAP analysis.</td></tr>
                    ) : iocs.map(r => (
                      <tr key={String(r.indicator_id)} className="border-b border-gray-800 hover:bg-gray-800/50 transition-colors">
                        <td className="px-4 py-3 text-gray-500">#{r.indicator_id}</td>
                        <td className="px-4 py-3"><span className="bg-gray-800 text-gray-300 text-xs px-2 py-0.5 rounded">{r.indicator_type}</span></td>
                        <td className="px-4 py-3 font-mono text-gray-200 text-xs max-w-[180px] truncate">{String(r.indicator_value)}</td>
                        <td className="px-4 py-3">{badge(String(r.severity))}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-1.5 bg-gray-700 rounded-full w-16">
                              <div className="h-1.5 bg-cyan-500 rounded-full" style={{ width: `${r.confidence_score}%` }} />
                            </div>
                            <span className="text-gray-400 text-xs">{r.confidence_score}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-gray-400 text-xs">{String(r.actor)}</td>
                        <td className="px-4 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full ${r.status === "Active" ? "bg-green-900 text-green-300" : "bg-gray-700 text-gray-400"}`}>{r.status}</span>
                        </td>
                        <td className="px-4 py-3">
                          <button onClick={() => deleteIOC(Number(r.indicator_id))}
                            className="text-gray-600 hover:text-red-400 transition-colors p-1 rounded">
                            <Trash2 size={14} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── ACTORS ────────────────────────────────── */}
          {tab === "actors" && (
            <div className="space-y-4">
              <h2 className="text-xl font-bold text-gray-200">Threat Actors</h2>
              <div className="grid grid-cols-2 gap-4">
                {actors.length === 0 ? (
                  <p className="text-gray-600 col-span-2 text-center py-10">No actors yet.</p>
                ) : actors.map(a => (
                  <div key={String(a.actor_id)} className="bg-gray-900 border border-gray-700 rounded-xl p-5 hover:border-gray-600 transition-colors">
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="font-bold text-gray-200">{a.actor_name}</p>
                        <p className="text-xs text-gray-500 mt-0.5">{a.origin_country} · {a.motivation}</p>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-bold
                        ${Number(a.sophistication_level) >= 4 ? "bg-red-900 text-red-300" :
                          Number(a.sophistication_level) >= 2 ? "bg-orange-900 text-orange-300" : "bg-green-900 text-green-300"}`}>
                        L{a.sophistication_level}
                      </span>
                    </div>
                    <div className="mt-3 flex gap-4 text-xs text-gray-500">
                      <span>IOCs: <span className="text-cyan-400 font-bold">{a.total_indicators}</span></span>
                      <span>Incidents: <span className="text-orange-400 font-bold">{a.incident_count}</span></span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── INCIDENTS ─────────────────────────────── */}
          {tab === "incidents" && (
            <div className="space-y-4">
              <h2 className="text-xl font-bold text-gray-200">Active Incidents</h2>
              <div className="space-y-3">
                {incidents.length === 0 ? (
                  <p className="text-gray-600 text-center py-10">No incidents.</p>
                ) : incidents.map(r => (
                  <div key={String(r.incident_id)} className="bg-gray-900 border border-gray-700 rounded-xl p-5 hover:border-gray-600 transition-colors">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-bold text-gray-200">{r.incident_title}</p>
                        <p className="text-xs text-gray-500 mt-0.5">
                          Actor: <span className="text-gray-300">{r.actor_name || "Unknown"}</span>
                          {" · "}Status: <span className="text-gray-300">{r.status}</span>
                        </p>
                      </div>
                      <div className="flex items-center gap-3">
                        {badge(String(r.severity))}
                        <span className={`text-xs px-2 py-0.5 rounded-full font-bold
                          ${r.sla_status === "BREACHED" ? "bg-red-900 text-red-300" : "bg-green-900 text-green-300"}`}>
                          SLA: {r.sla_status}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ── AUDIT LOG ─────────────────────────────── */}
          {tab === "audit" && (
            <div className="space-y-4">
              <h2 className="text-xl font-bold text-gray-200">Audit Log</h2>
              <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
                <table className="w-full text-sm font-mono">
                  <thead>
                    <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                      <th className="text-left px-4 py-3">ID</th>
                      <th className="text-left px-4 py-3">Table</th>
                      <th className="text-left px-4 py-3">Operation</th>
                      <th className="text-left px-4 py-3">Record</th>
                      <th className="text-left px-4 py-3">By</th>
                      <th className="text-left px-4 py-3">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {audit.length === 0 ? (
                      <tr><td colSpan={6} className="text-center text-gray-600 py-10">No audit entries yet — add data via Java CLI to trigger the audit log.</td></tr>
                    ) : audit.map(r => (
                      <tr key={String(r.log_id)} className="border-b border-gray-800 text-xs hover:bg-gray-800/50">
                        <td className="px-4 py-2.5 text-gray-600">#{r.log_id}</td>
                        <td className="px-4 py-2.5 text-gray-300">{r.table_name}</td>
                        <td className="px-4 py-2.5">
                          <span className={`px-2 py-0.5 rounded font-bold
                            ${r.operation === "INSERT" ? "bg-green-900/40 text-green-400" :
                              r.operation === "UPDATE" ? "bg-yellow-900/40 text-yellow-400" :
                              "bg-red-900/40 text-red-400"}`}>
                            {r.operation}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-gray-400">{r.record_id}</td>
                        <td className="px-4 py-2.5 text-gray-400">#{r.performed_by}</td>
                        <td className="px-4 py-2.5 text-gray-500">{new Date(String(r.performed_at)).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── USERS ─────────────────────────────────── */}
          {tab === "users" && (
            <div className="space-y-6">
              <h2 className="text-xl font-bold text-gray-200">User Management</h2>

              {/* Current users from DB */}
              <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
                  <h3 className="font-bold text-gray-300 text-sm uppercase tracking-wider">All Users</h3>
                  <span className="text-xs text-gray-500">{users.length} accounts in database</span>
                </div>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                      <th className="text-left px-5 py-3">ID</th>
                      <th className="text-left px-5 py-3">Username</th>
                      <th className="text-left px-5 py-3">Email</th>
                      <th className="text-left px-5 py-3">Role</th>
                      <th className="text-left px-5 py-3">Department</th>
                      <th className="text-left px-5 py-3">Active</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.length === 0 ? (
                      <tr><td colSpan={6} className="text-center text-gray-600 py-8">No users found.</td></tr>
                    ) : users.map(u => (
                      <tr key={String(u.user_id)} className="border-b border-gray-800 hover:bg-gray-800/40 transition-colors">
                        <td className="px-5 py-3 text-gray-500 text-xs">#{u.user_id}</td>
                        <td className="px-5 py-3 font-mono text-gray-200 font-bold">{u.username}</td>
                        <td className="px-5 py-3 text-gray-400 text-xs">{u.email || "—"}</td>
                        <td className="px-5 py-3">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-bold capitalize
                            ${String(u.role) === "admin"
                              ? "bg-lime-900/40 text-lime-400 border border-lime-800"
                              : "bg-cyan-900/40 text-cyan-400 border border-cyan-800"}`}>
                            {u.role}
                          </span>
                        </td>
                        <td className="px-5 py-3 text-gray-400 text-xs">{u.department || "—"}</td>
                        <td className="px-5 py-3">
                          {u.is_active
                            ? <CheckCircle size={14} className="text-green-400" />
                            : <XCircle    size={14} className="text-red-400" />}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Create new analyst */}
              <div className="bg-gray-900 border border-cyan-900 rounded-xl p-6 space-y-4">
                <div className="flex items-center gap-2 mb-1">
                  <UserPlus size={18} className="text-cyan-400" />
                  <h3 className="font-bold text-gray-200">Create New Analyst Account</h3>
                </div>
                <p className="text-gray-500 text-xs">Only admins can create accounts. New user will be able to log in immediately.</p>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-wider">Username *</label>
                    <input
                      value={newUser.username}
                      onChange={e => setNewUser(p => ({ ...p, username: e.target.value }))}
                      placeholder="analyst_username"
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm font-mono focus:outline-none focus:border-cyan-600"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-wider">Password *</label>
                    <input
                      type="text"
                      value={newUser.password}
                      onChange={e => setNewUser(p => ({ ...p, password: e.target.value }))}
                      placeholder="set a password"
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm font-mono focus:outline-none focus:border-cyan-600"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-wider">Email</label>
                    <input
                      value={newUser.email}
                      onChange={e => setNewUser(p => ({ ...p, email: e.target.value }))}
                      placeholder="analyst@ctims.local"
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500 uppercase tracking-wider">Department</label>
                    <select
                      value={newUser.department}
                      onChange={e => setNewUser(p => ({ ...p, department: e.target.value }))}
                      className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600 appearance-none">
                      <option>Threat Intelligence</option>
                      <option>Incident Response</option>
                      <option>Malware Analysis</option>
                      <option>Network Security</option>
                      <option>Vulnerability Management</option>
                      <option>SOC Operations</option>
                      <option>Digital Forensics</option>
                      <option>Red Team</option>
                      <option>Blue Team</option>
                      <option>Cyber Security</option>
                    </select>
                  </div>
                </div>

                <div className="flex items-center gap-4 pt-1">
                  <button
                    onClick={createAnalyst}
                    disabled={!newUser.username || !newUser.password}
                    className="flex items-center gap-2 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-white px-5 py-2.5 rounded-xl font-bold text-sm transition-colors">
                    <UserPlus size={15} /> Create Analyst
                  </button>
                  {createMsg && (
                    <p className={`text-sm font-mono ${createMsg.startsWith("✓") ? "text-green-400" : "text-red-400"}`}>
                      {createMsg}
                    </p>
                  )}
                </div>
              </div>

              <div className="bg-gray-900 border border-yellow-900/50 rounded-xl p-4 text-sm text-yellow-600">
                <strong className="text-yellow-500">Java OOP note:</strong> Admin count tracked via <code className="text-yellow-400">static int adminCount</code> in Admin.java. Role-based access enforced via <code className="text-yellow-400">canAccess()</code> polymorphism.
              </div>
            </div>
          )}

        </main>
      </div>

      {/* ── Analyst Notification Stack (bottom-right) ─────────────── */}
      {notifs.length > 0 && (
        <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 w-96">
          {notifs.map((n) => {
            const sevColor: Record<string, { card: string; badge: string; bar: string }> = {
              Critical: { card: "border-red-600 bg-red-950/95",    badge: "bg-red-600 text-white",    bar: "bg-red-500" },
              High:     { card: "border-orange-500 bg-orange-950/95", badge: "bg-orange-500 text-white", bar: "bg-orange-400" },
              Medium:   { card: "border-yellow-500 bg-yellow-950/95", badge: "bg-yellow-500 text-black", bar: "bg-yellow-400" },
              Low:      { card: "border-green-600 bg-green-950/95", badge: "bg-green-600 text-white",  bar: "bg-green-400" },
            };
            const c = sevColor[n.severity] ?? sevColor.Medium;

            return (
              <div key={n.id}
                className={`rounded-2xl border-2 p-4 shadow-2xl backdrop-blur-sm animate-in slide-in-from-right-4 ${c.card}`}
                style={{ animation: "slideInRight 0.3s ease-out" }}>

                {/* Header */}
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-full bg-cyan-900/60 flex items-center justify-center">
                      <User size={15} className="text-cyan-400" />
                    </div>
                    <div>
                      <p className="text-xs font-bold text-gray-200">
                        Report from <span className="text-cyan-400">{n.submitted_by}</span>
                      </p>
                      <p className="text-xs text-gray-500">{n.timestamp}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${c.badge}`}>
                      {n.severity}
                    </span>
                    <button onClick={() => dismissNotif(n.id)}
                      className="text-gray-500 hover:text-gray-300 transition-colors p-0.5 rounded">
                      <X size={14} />
                    </button>
                  </div>
                </div>

                {/* IOC detail */}
                <div className="bg-black/30 rounded-xl p-3 mb-3">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded font-mono">{n.type}</span>
                    <span className="text-xs text-gray-500">#{String(Math.floor(Math.random()*9000+1000))}</span>
                  </div>
                  <p className="text-sm font-mono text-white font-bold break-all">{n.value}</p>
                  {n.context && (
                    <p className="text-xs text-gray-400 mt-1.5 leading-relaxed">{n.context}</p>
                  )}
                </div>

                {/* Confidence bar */}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-500 w-20 shrink-0">Confidence</span>
                  <div className="flex-1 h-1.5 bg-gray-700 rounded-full">
                    <div className={`h-1.5 rounded-full ${c.bar}`} style={{ width: `${n.confidence}%` }} />
                  </div>
                  <span className="text-xs text-gray-400 w-8 text-right">{n.confidence}%</span>
                </div>

                {/* Action buttons */}
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={() => { setTab("iocs"); dismissNotif(n.id); load(); }}
                    className="flex-1 text-xs bg-cyan-800/60 hover:bg-cyan-700/80 text-cyan-300 py-1.5 rounded-lg font-bold transition-colors">
                    View in IOC Manager →
                  </button>
                  <button onClick={() => dismissNotif(n.id)}
                    className="text-xs bg-gray-700/60 hover:bg-gray-600/80 text-gray-400 px-3 py-1.5 rounded-lg transition-colors">
                    Dismiss
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
      `}</style>
    </div>
  );
}
