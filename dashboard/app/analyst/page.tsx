"use client";
import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Shield, Activity, AlertTriangle, LogOut, User,
  PlusCircle, CheckCircle, RefreshCw, Send, Upload, Radio
} from "lucide-react";

import { API } from "@/lib/api";

interface Me { user_id: number; username: string; role: string; email: string; department: string }
type Row = Record<string, string | number | boolean | null>;

const badge = (s: string) => {
  const c: Record<string,string> = {
    Critical:"bg-red-900 text-red-300", High:"bg-orange-900 text-orange-300",
    Medium:"bg-yellow-900 text-yellow-300", Low:"bg-green-900 text-green-300",
  };
  return <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${c[s] ?? "bg-gray-700 text-gray-300"}`}>{s}</span>;
};

const SEVERITY = ["Critical","High","Medium","Low"];
const IOC_TYPES = ["IP","Domain","URL","Hash","Email"];

export default function AnalystPage() {
  const router = useRouter();
  const [me,        setMe]        = useState<Me | null>(null);
  const [incidents, setIncidents] = useState<Row[]>([]);
  const [iocs,      setIocs]      = useState<Row[]>([]);
  const [stats,     setStats]     = useState<Row | null>(null);
  const [loading,   setLoading]   = useState(true);
  const [submitted, setSubmitted] = useState<string[]>([]);
  const [tab,       setTab]       = useState<"incidents"|"iocs"|"submit">("incidents");

  // IOC form state
  const [form, setForm] = useState({
    indicator_type: "IP", indicator_value: "",
    severity: "Medium", confidence_score: 70,
    context: "",
  });
  // Type-specific extra fields (mirrors Java subclass constructors)
  const [extra, setExtra] = useState({
    ip_version: "IPv4", geolocation: "",           // IP
    registrar: "", is_dga: "no",                   // Domain
    has_redirect: "no",                            // URL
    hash_type: "SHA256", file_name: "",            // Hash
  });
  const [submitStatus, setSubmitStatus] = useState("");

  const setE = (k: keyof typeof extra, v: string) =>
    setExtra(p => ({ ...p, [k]: v }));

  useEffect(() => {
    const raw = localStorage.getItem("ctims_user");
    if (!raw) { router.push("/login"); return; }
    const u = JSON.parse(raw) as Me;
    if (u.role.toLowerCase() === "admin") { router.push("/admin"); return; }
    setMe(u);
  }, [router]);

  const safeFetch = async (url: string) => {
    try { const r = await fetch(url); return r.ok ? r.json() : null; }
    catch { return null; }
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, inc, i] = await Promise.all([
        safeFetch(`${API}/api/stats`),
        safeFetch(`${API}/api/incidents`),
        safeFetch(`${API}/api/indicators`),
      ]);
      if (s) setStats(s.dashboard);
      if (Array.isArray(inc)) setIncidents(inc);
      if (Array.isArray(i))   setIocs(i.slice(0, 20));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { if (me) load(); }, [me, load]);

  const logout = () => { localStorage.removeItem("ctims_user"); router.push("/login"); };

  const buildContext = () => {
    const notes = form.context.trim();
    const parts: string[] = [];
    if (form.indicator_type === "IP") {
      parts.push(`IP Version: ${extra.ip_version}`);
      if (extra.geolocation) parts.push(`Geolocation: ${extra.geolocation}`);
    } else if (form.indicator_type === "Domain") {
      parts.push(`DGA: ${extra.is_dga}`);
      if (extra.registrar) parts.push(`Registrar: ${extra.registrar}`);
    } else if (form.indicator_type === "URL") {
      parts.push(`Has Redirect: ${extra.has_redirect}`);
    } else if (form.indicator_type === "Hash") {
      parts.push(`Hash Type: ${extra.hash_type}`);
      if (extra.file_name) parts.push(`File: ${extra.file_name}`);
    }
    return parts.length ? `${parts.join(" | ")}${notes ? " | " + notes : ""}` : notes;
  };

  const submitIOC = async () => {
    if (!form.indicator_value.trim()) return;
    setSubmitStatus("Submitting…");
    try {
      const res = await fetch(`${API}/api/indicators`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...form,
          context: buildContext(),
          is_malicious: true,
          submitted_by: me?.username ?? "analyst",
        }),
      });
      const d = await res.json();
      if (d.success) {
        setSubmitStatus(`Saved (ID #${d.id}) — DB trigger fired automatically`);
        setSubmitted(prev => [...prev, form.indicator_value]);
        setForm(f => ({ ...f, indicator_value: "", context: "" }));
        load();
      } else {
        setSubmitStatus("Error: " + (d.detail ?? d.error));
      }
    } catch {
      setSubmitStatus("Error: Could not reach server");
    }
  };

  if (!me || loading) return (
    <div className="min-h-screen flex items-center justify-center text-cyan-400 animate-pulse text-lg"
      style={{ background: "#0b0e14" }}>
      Loading Analyst Dashboard…
    </div>
  );

  return (
    <div className="min-h-screen" style={{ background: "#0b0e14" }}>
      {/* Top nav */}
      <header className="flex items-center justify-between px-6 py-4 border-b"
        style={{ background: "#0d1117", borderColor: "#1e2a3a" }}>
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg" style={{ background: "#1e2a3a", boxShadow: "0 0 12px rgba(6,182,212,0.35)" }}>
            <Shield size={20} className="text-cyan-400" />
          </div>
          <div>
            <span className="font-bold tracking-widest text-sm text-cyan-400">CTIMS</span>
            <span className="text-gray-600 text-xs ml-3">Analyst Dashboard</span>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-2 text-sm text-gray-300">
            <div className="w-7 h-7 rounded-full bg-cyan-900 flex items-center justify-center">
              <User size={14} className="text-cyan-400" />
            </div>
            {me.email ? me.email.split("@")[0] : me.username}
            <span className="text-xs bg-cyan-900/40 border border-cyan-800 text-cyan-400 px-2 py-0.5 rounded-full">Analyst</span>
          </span>
          <button onClick={() => load()} className="text-gray-500 hover:text-gray-300 p-1.5 rounded-lg hover:bg-gray-800">
            <RefreshCw size={15} />
          </button>
          <button onClick={logout}
            className="flex items-center gap-2 bg-red-900/30 hover:bg-red-800/60 border border-red-800 text-red-400 hover:text-red-300 text-sm px-3 py-1.5 rounded-lg transition-all font-medium">
            <LogOut size={15} /> Sign Out
          </button>
        </div>
      </header>

      <div className="max-w-5xl mx-auto p-6 space-y-6">

        {/* Welcome banner */}
        <div className="bg-cyan-950/40 border border-cyan-900 rounded-xl p-5 flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-cyan-900/60 flex items-center justify-center text-2xl font-bold text-cyan-400 shrink-0">
            {(me.email ? me.email.split("@")[0] : me.username)[0]}
          </div>
          <div>
            <p className="font-bold text-gray-200">Welcome, {me.email ? me.email.split("@")[0] : me.username}</p>
            <p className="text-sm text-gray-500">Analyst · Access: Incidents + IOC Reporting only</p>
            <p className="text-xs text-gray-600 mt-0.5">Restricted: Cannot delete indicators or view audit log. Report threats below.</p>
          </div>
        </div>

        {/* Mini stat cards */}
        <div className="grid grid-cols-4 gap-3">
          {[
            { label:"Open Incidents",   val: stats?.open_incidents      ?? 0, color:"text-orange-400", icon: AlertTriangle },
            { label:"Active Indicators",val: stats?.active_indicators   ?? 0, color:"text-cyan-400",   icon: Activity },
            { label:"Critical IOCs",    val: stats?.critical_indicators  ?? 0, color:"text-red-400",    icon: Shield },
            { label:"I Submitted",      val: submitted.length,                color:"text-green-400",   icon: CheckCircle },
          ].map(({ label, val, color, icon: Icon }) => (
            <div key={label} className="bg-gray-900 border border-gray-700 rounded-xl p-4">
              <div className="flex items-center justify-between">
                <p className="text-gray-500 text-xs">{label}</p>
                <Icon size={16} className={color} />
              </div>
              <p className={`text-2xl font-bold mt-1 ${color}`}>{val}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-gray-900 border border-gray-700 rounded-xl p-1">
          {([
            { id:"incidents", label:"Assigned Incidents", icon: AlertTriangle, link: null },
            { id:"iocs",      label:"Recent IOCs",        icon: Activity,     link: null },
            { id:"submit",    label:"Report Threat",      icon: Send,         link: null },
            { id:"pcap",      label:"PCAP Analysis",      icon: Upload,       link: "/upload" },
            { id:"capture",   label:"Live Capture",       icon: Radio,        link: "/capture" },
          ] as { id: string; label: string; icon: typeof AlertTriangle; link: string | null }[]).map(({ id, label, icon: Icon, link }) => (
            <button key={id} onClick={() => link ? router.push(link) : setTab(id as "incidents"|"iocs"|"submit")}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 rounded-lg text-sm font-medium transition-all
                ${!link && tab === id ? "bg-cyan-900/40 text-cyan-300 border border-cyan-800"
                  : link ? "text-cyan-500 hover:text-cyan-300"
                  : "text-gray-500 hover:text-gray-300"}`}>
              <Icon size={14} />
              <span className="hidden sm:inline">{label}</span>
              {link && <span className="text-xs opacity-40">↗</span>}
            </button>
          ))}
        </div>

        {/* ── INCIDENTS ─────────────────────────────── */}
        {tab === "incidents" && (
          <div className="space-y-3">
            {incidents.length === 0 ? (
              <div className="text-center text-gray-600 py-12">
                <AlertTriangle size={32} className="mx-auto mb-3 opacity-30" />
                <p>No open incidents. System is clear.</p>
              </div>
            ) : incidents.map(r => (
              <div key={String(r.incident_id)} className="bg-gray-900 border border-gray-700 rounded-xl p-5 hover:border-gray-600 transition-colors">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-bold text-gray-200">{r.incident_title}</p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      #{r.incident_id} · Actor: <span className="text-gray-300">{r.actor_name || "Unknown"}</span>
                      {" · "}{r.status}
                    </p>
                    {r.description && (
                      <p className="text-xs text-gray-600 mt-1.5 max-w-xl">{String(r.description).slice(0,120)}</p>
                    )}
                  </div>
                  <div className="flex flex-col items-end gap-2">
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
        )}

        {/* ── RECENT IOCs ───────────────────────────── */}
        {tab === "iocs" && (
          <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                  <th className="text-left px-4 py-3">Type</th>
                  <th className="text-left px-4 py-3">Value</th>
                  <th className="text-left px-4 py-3">Severity</th>
                  <th className="text-left px-4 py-3">Confidence</th>
                  <th className="text-left px-4 py-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {iocs.length === 0 ? (
                  <tr><td colSpan={5} className="text-center text-gray-600 py-10">No indicators yet.</td></tr>
                ) : iocs.map(r => (
                  <tr key={String(r.indicator_id)} className="border-b border-gray-800 text-xs hover:bg-gray-800/50">
                    <td className="px-4 py-2.5"><span className="bg-gray-800 text-gray-300 px-2 py-0.5 rounded">{r.indicator_type}</span></td>
                    <td className="px-4 py-2.5 font-mono text-gray-200 max-w-[220px] truncate">{String(r.indicator_value)}</td>
                    <td className="px-4 py-2.5">{badge(String(r.severity))}</td>
                    <td className="px-4 py-2.5 text-gray-400">{r.confidence_score}%</td>
                    <td className="px-4 py-2.5">
                      <span className={`px-2 py-0.5 rounded-full font-bold ${r.status === "Active" ? "bg-green-900/40 text-green-400" : "bg-gray-700 text-gray-500"}`}>{r.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── SUBMIT IOC ────────────────────────────── */}
        {tab === "submit" && (
          <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 space-y-5">
            <div>
              <h3 className="text-lg font-bold text-gray-200">Report a New Threat Indicator</h3>
              <p className="text-gray-500 text-sm mt-1">
                Submitted IOCs are saved to the CTIMS database. Triggers will fire automatically.
              </p>
            </div>

            {/* Row 1: Type + Severity */}
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-gray-500 uppercase tracking-wider">IOC Type</label>
                <select value={form.indicator_type}
                  onChange={e => setForm(f => ({ ...f, indicator_type: e.target.value }))}
                  className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600">
                  {IOC_TYPES.map(t => <option key={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-gray-500 uppercase tracking-wider">Severity</label>
                <select value={form.severity}
                  onChange={e => setForm(f => ({ ...f, severity: e.target.value }))}
                  className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600">
                  {SEVERITY.map(s => <option key={s}>{s}</option>)}
                </select>
              </div>
            </div>

            {/* Indicator Value */}
            <div>
              <label className="text-xs text-gray-500 uppercase tracking-wider">Indicator Value</label>
              <input value={form.indicator_value}
                onChange={e => setForm(f => ({ ...f, indicator_value: e.target.value }))}
                placeholder={
                  form.indicator_type === "IP"     ? "e.g. 45.33.32.156" :
                  form.indicator_type === "Domain" ? "e.g. evil.tk" :
                  form.indicator_type === "URL"    ? "e.g. http://evil.tk/payload.exe" :
                  form.indicator_type === "Hash"   ? "e.g. d41d8cd98f00b204e9800998ecf8427e" :
                  "e.g. attacker@evil.com"
                }
                className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm font-mono focus:outline-none focus:border-cyan-600"
              />
            </div>

            {/* ── Dynamic type-specific fields ── */}
            {form.indicator_type === "IP" && (
              <div className="grid grid-cols-2 gap-4 p-4 bg-gray-800/50 border border-cyan-900/40 rounded-xl">
                <p className="col-span-2 text-xs text-cyan-500 font-bold uppercase tracking-wider mb-1">
                  IP-specific fields — maps to IPIndicator.java
                </p>
                <div>
                  <label className="text-xs text-gray-500 uppercase tracking-wider">IP Version</label>
                  <select value={extra.ip_version} onChange={e => setE("ip_version", e.target.value)}
                    className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600">
                    <option>IPv4</option>
                    <option>IPv6</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-gray-500 uppercase tracking-wider">Geolocation</label>
                  <input value={extra.geolocation} onChange={e => setE("geolocation", e.target.value)}
                    placeholder="e.g. Mumbai, India"
                    className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600"
                  />
                </div>
              </div>
            )}

            {form.indicator_type === "Domain" && (
              <div className="grid grid-cols-2 gap-4 p-4 bg-gray-800/50 border border-purple-900/40 rounded-xl">
                <p className="col-span-2 text-xs text-purple-400 font-bold uppercase tracking-wider mb-1">
                  Domain-specific fields — maps to DomainIndicator.java
                </p>
                <div>
                  <label className="text-xs text-gray-500 uppercase tracking-wider">Is DGA Domain?</label>
                  <select value={extra.is_dga} onChange={e => setE("is_dga", e.target.value)}
                    className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600">
                    <option value="no">No</option>
                    <option value="yes">Yes — Algorithmically Generated</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-gray-500 uppercase tracking-wider">Registrar</label>
                  <input value={extra.registrar} onChange={e => setE("registrar", e.target.value)}
                    placeholder="e.g. NameCheap"
                    className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600"
                  />
                </div>
              </div>
            )}

            {form.indicator_type === "URL" && (
              <div className="p-4 bg-gray-800/50 border border-orange-900/40 rounded-xl">
                <p className="text-xs text-orange-400 font-bold uppercase tracking-wider mb-3">
                  URL-specific fields — maps to URLIndicator.java
                </p>
                <div>
                  <label className="text-xs text-gray-500 uppercase tracking-wider">Has Redirect?</label>
                  <select value={extra.has_redirect} onChange={e => setE("has_redirect", e.target.value)}
                    className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600">
                    <option value="no">No</option>
                    <option value="yes">Yes — URL redirects to another destination</option>
                  </select>
                </div>
              </div>
            )}

            {form.indicator_type === "Hash" && (
              <div className="grid grid-cols-2 gap-4 p-4 bg-gray-800/50 border border-yellow-900/40 rounded-xl">
                <p className="col-span-2 text-xs text-yellow-400 font-bold uppercase tracking-wider mb-1">
                  Hash-specific fields — maps to HashIndicator.java
                </p>
                <div>
                  <label className="text-xs text-gray-500 uppercase tracking-wider">Hash Type</label>
                  <select value={extra.hash_type} onChange={e => setE("hash_type", e.target.value)}
                    className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600">
                    <option>MD5</option>
                    <option>SHA1</option>
                    <option>SHA256</option>
                    <option>SHA512</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-gray-500 uppercase tracking-wider">File Name</label>
                  <input value={extra.file_name} onChange={e => setE("file_name", e.target.value)}
                    placeholder="e.g. payload.exe"
                    className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600"
                  />
                </div>
              </div>
            )}

            {/* Confidence */}
            <div>
              <label className="text-xs text-gray-500 uppercase tracking-wider">
                Confidence Score: <span className="text-cyan-400 font-bold">{form.confidence_score}%</span>
              </label>
              <input type="range" min={1} max={100} value={form.confidence_score}
                onChange={e => setForm(f => ({ ...f, confidence_score: Number(e.target.value) }))}
                className="mt-1 w-full accent-cyan-500"
              />
            </div>

            {/* Context */}
            <div>
              <label className="text-xs text-gray-500 uppercase tracking-wider">Context / Notes</label>
              <textarea value={form.context}
                onChange={e => setForm(f => ({ ...f, context: e.target.value }))}
                rows={3}
                placeholder="How was this IOC observed? Any additional context…"
                className="mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-gray-200 text-sm focus:outline-none focus:border-cyan-600 resize-none"
              />
            </div>

            {/* Submit */}
            <div className="flex items-center gap-4">
              <button onClick={submitIOC} disabled={!form.indicator_value.trim()}
                className="flex items-center gap-2 bg-cyan-700 hover:bg-cyan-600 disabled:opacity-40 text-white px-6 py-2.5 rounded-xl font-bold text-sm transition-colors">
                <Send size={16} /> Submit Indicator
              </button>
              {submitStatus && (
                <p className={`text-sm font-mono ${submitStatus.startsWith("Error") ? "text-red-400" : "text-green-400"}`}>
                  {submitStatus}
                </p>
              )}
            </div>

            {submitted.length > 0 && (
              <div className="border-t border-gray-800 pt-4">
                <p className="text-xs text-gray-500 mb-2">Submitted this session:</p>
                <div className="flex flex-wrap gap-2">
                  {submitted.map(v => (
                    <span key={v} className="flex items-center gap-1 bg-green-900/30 border border-green-800 text-green-400 text-xs px-2 py-1 rounded-lg font-mono">
                      <CheckCircle size={11} /> {v}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

      </div>
    </div>
  );
}
