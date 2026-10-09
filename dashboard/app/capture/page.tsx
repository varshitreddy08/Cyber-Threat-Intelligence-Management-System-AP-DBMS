"use client";
import { useState, useEffect, useRef, useCallback } from "react";
import {
  Radio, Square, ChevronDown, AlertTriangle, Shield,
  Wifi, Filter, Trash2, Download, PlusCircle, CheckCircle
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { wsUrl } from "@/lib/api";

// ── Types ─────────────────────────────────────────────────────────────
interface Iface  { id: string; device: string; name: string }
interface Packet {
  no: number; time: number; src: string; dst: string;
  proto: string; len: number; info: string; suspicious: boolean;
}
interface Alert  { no: number; src: string; dst: string; proto: string; info: string }

// ── Protocol color map (Wireshark-inspired) ────────────────────────────
const PROTO_COLORS: Record<string, string> = {
  DNS:    "bg-blue-950 text-blue-300 border-blue-900",
  HTTP:   "bg-green-950 text-green-300 border-green-900",
  TLS:    "bg-teal-950 text-teal-300 border-teal-900",
  SSL:    "bg-teal-950 text-teal-300 border-teal-900",
  TCP:    "bg-gray-900 text-gray-300 border-gray-800",
  UDP:    "bg-yellow-950 text-yellow-300 border-yellow-900",
  ARP:    "bg-purple-950 text-purple-300 border-purple-900",
  ICMP:   "bg-orange-950 text-orange-300 border-orange-900",
  IRC:    "bg-red-950 text-red-300 border-red-900",
  DATA:   "bg-gray-950 text-gray-500 border-gray-900",
  MDNS:   "bg-blue-950 text-blue-400 border-blue-900",
  DHCP:   "bg-indigo-950 text-indigo-300 border-indigo-900",
  NTP:    "bg-slate-900 text-slate-400 border-slate-800",
};

function protoStyle(proto: string, susp: boolean): string {
  if (susp) return "bg-red-950 text-red-300 border-red-900";
  return PROTO_COLORS[proto] ?? "bg-gray-900 text-gray-400 border-gray-800";
}

// ── Suggested IOC severity helper ──────────────────────────────────────
const SUSP_PORTS: Record<number, string> = {
  4444:"Metasploit", 1337:"C2", 6667:"IRC botnet", 31337:"Backdoor",
  3389:"RDP", 23:"Telnet", 1433:"MSSQL", 12345:"NetBus"
};

export default function CapturePage() {
  const [ifaces,      setIfaces]      = useState<Iface[]>([]);
  const [selIface,    setSelIface]    = useState("");
  const [bpfFilter,   setBpfFilter]   = useState("");
  const [capturing,   setCapturing]   = useState(false);
  const [packets,     setPackets]     = useState<Packet[]>([]);
  const [alerts,      setAlerts]      = useState<Alert[]>([]);
  const [protoStats,  setProtoStats]  = useState<{name:string;count:number}[]>([]);
  const [status,      setStatus]      = useState("Ready");
  const [selPkt,      setSelPkt]      = useState<Packet | null>(null);
  const [saved,       setSaved]       = useState<Set<string>>(new Set());
  const [autoScroll,  setAutoScroll]  = useState(true);

  const wsRef       = useRef<WebSocket | null>(null);
  const tableRef    = useRef<HTMLDivElement>(null);
  const protoMap    = useRef<Record<string, number>>({});
  const pktCountRef = useRef(0);

  // Load interfaces
  useEffect(() => {
    fetch("/api/interfaces")
      .then(r => r.json())
      .then((list: Iface[]) => {
        setIfaces(list);
        if (list.length > 0) setSelIface(list[0].id);
      })
      .catch(() => setStatus("Could not load interfaces — is FastAPI running?"));
  }, []);

  // Auto-scroll packet list
  useEffect(() => {
    if (autoScroll && tableRef.current) {
      tableRef.current.scrollTop = tableRef.current.scrollHeight;
    }
  }, [packets, autoScroll]);

  const rebuildProtoStats = useCallback(() => {
    const stats = Object.entries(protoMap.current)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([name, count]) => ({ name, count }));
    setProtoStats(stats);
  }, []);

  // ── Start capture ────────────────────────────────────────────────────
  const startCapture = useCallback(() => {
    if (!selIface) return;
    setPackets([]);
    setAlerts([]);
    setSelPkt(null);
    protoMap.current = {};
    pktCountRef.current = 0;
    setProtoStats([]);

    const ws = new WebSocket(wsUrl("/ws/capture"));
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ cmd: "start", iface: selIface, filter: bpfFilter }));
      setCapturing(true);
      setStatus("Capturing…");
    };

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data);

      if (msg.type === "started") {
        setStatus(`Capturing on interface ${msg.iface}`);
      } else if (msg.type === "packet") {
        const pkt: Packet = msg.data;
        setPackets(prev => {
          const next = prev.length >= 5000 ? prev.slice(-4000) : prev;
          return [...next, pkt];
        });
        protoMap.current[pkt.proto] = (protoMap.current[pkt.proto] ?? 0) + 1;
        pktCountRef.current += 1;
        if (pktCountRef.current % 20 === 0) rebuildProtoStats();
      } else if (msg.type === "alert") {
        const a: Alert = msg.data;
        setAlerts(prev => [a, ...prev].slice(0, 50));
      } else if (msg.type === "error") {
        setStatus(`Error: ${msg.msg}`);
        setCapturing(false);
      } else if (msg.type === "stopped") {
        setStatus(`Stopped — ${msg.total} packets captured`);
        setCapturing(false);
        rebuildProtoStats();
      }
    };

    ws.onerror = () => {
      setStatus("WebSocket error — is FastAPI running on port 8000?");
      setCapturing(false);
    };

    ws.onclose = () => {
      if (capturing) setCapturing(false);
    };
  }, [selIface, bpfFilter, rebuildProtoStats, capturing]);

  // ── Stop capture ─────────────────────────────────────────────────────
  const stopCapture = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ cmd: "stop" }));
    }
    setCapturing(false);
  }, []);

  // Clear packets
  const clearAll = () => {
    setPackets([]);
    setAlerts([]);
    setSelPkt(null);
    protoMap.current = {};
    setProtoStats([]);
    setStatus("Ready");
  };

  // Save IOC from alert
  const saveIOC = async (pkt: Alert) => {
    const key = pkt.src;
    const payload = {
      indicator_type: "IP",
      indicator_value: pkt.src,
      severity: "High",
      is_malicious: true,
      confidence_score: 75,
      context: `Live capture: ${pkt.info} (packet #${pkt.no})`,
    };
    await fetch("/api/indicators", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setSaved(prev => new Set([...prev, key]));
  };

  // Export captured packets as JSON
  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(packets, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `ctims_capture_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* ── Header ──────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-cyan-400 flex items-center gap-2">
            <Radio size={22} className={capturing ? "text-red-400 animate-pulse" : "text-cyan-400"} />
            Live Packet Capture
          </h1>
          <p className="text-gray-500 text-sm mt-1">Real-time network capture powered by tshark · Wireshark engine</p>
        </div>
        <div className="flex items-center gap-2">
          {capturing && (
            <span className="flex items-center gap-1.5 text-xs text-red-400 bg-red-900/20 border border-red-800 px-3 py-1.5 rounded-full animate-pulse">
              ● CAPTURING
            </span>
          )}
          <span className="text-xs text-gray-500 bg-gray-800 border border-gray-700 px-3 py-1.5 rounded-full">
            {packets.length} packets
          </span>
        </div>
      </div>

      {/* ── Toolbar ─────────────────────────────────────── */}
      <div className="flex items-center gap-3 flex-wrap">
        {/* Interface selector */}
        <div className="relative">
          <select
            value={selIface}
            onChange={e => setSelIface(e.target.value)}
            disabled={capturing}
            className="bg-gray-900 border border-gray-700 text-gray-200 text-sm rounded-lg px-3 py-2 pr-8 appearance-none focus:outline-none focus:border-cyan-600 disabled:opacity-50 min-w-52">
            {ifaces.length === 0 && <option value="">Loading interfaces…</option>}
            {ifaces.map(i => (
              <option key={i.id} value={i.id}>{i.id}. {i.name}</option>
            ))}
          </select>
          <ChevronDown size={14} className="absolute right-2 top-3 text-gray-500 pointer-events-none" />
        </div>

        {/* BPF filter */}
        <div className="flex items-center gap-1.5 flex-1 min-w-48 bg-gray-900 border border-gray-700 rounded-lg px-3 py-2">
          <Filter size={14} className="text-gray-500 shrink-0" />
          <input
            value={bpfFilter}
            onChange={e => setBpfFilter(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !capturing && startCapture()}
            disabled={capturing}
            placeholder="BPF filter e.g. tcp port 80 or host 8.8.8.8"
            className="bg-transparent text-sm text-gray-200 placeholder-gray-600 focus:outline-none w-full disabled:opacity-50"
          />
        </div>

        {/* Quick filter chips */}
        {!capturing && (
          <div className="flex gap-1.5 flex-wrap">
            {["tcp", "udp", "dns", "http", "icmp"].map(f => (
              <button key={f} onClick={() => setBpfFilter(f)}
                className={`text-xs px-2.5 py-1 rounded-full border transition-colors
                  ${bpfFilter === f
                    ? "bg-cyan-900/40 border-cyan-700 text-cyan-300"
                    : "bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-500"}`}>
                {f}
              </button>
            ))}
            {bpfFilter && (
              <button onClick={() => setBpfFilter("")}
                className="text-xs px-2 py-1 rounded-full border border-gray-700 text-gray-500 hover:text-gray-300">
                ✕ clear
              </button>
            )}
          </div>
        )}

        <div className="flex gap-2 ml-auto">
          {!capturing ? (
            <button onClick={startCapture} disabled={!selIface}
              className="flex items-center gap-2 bg-red-700 hover:bg-red-600 disabled:opacity-40 text-white px-4 py-2 rounded-lg font-bold text-sm transition-colors">
              <Radio size={16} /> Start Capture
            </button>
          ) : (
            <button onClick={stopCapture}
              className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-lg font-bold text-sm transition-colors">
              <Square size={14} /> Stop
            </button>
          )}
          <button onClick={clearAll} disabled={capturing}
            className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 disabled:opacity-40 text-gray-300 px-3 py-2 rounded-lg text-sm transition-colors">
            <Trash2 size={14} />
          </button>
          {packets.length > 0 && (
            <button onClick={exportJSON}
              className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg text-sm transition-colors">
              <Download size={14} />
            </button>
          )}
        </div>
      </div>

      {/* ── Status bar ──────────────────────────────────── */}
      <div className="flex items-center gap-3 text-xs text-gray-500 px-1">
        <Wifi size={12} className={capturing ? "text-red-400" : "text-gray-600"} />
        <span>{status}</span>
        <label className="flex items-center gap-1 ml-auto cursor-pointer">
          <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} className="accent-cyan-500" />
          Auto-scroll
        </label>
      </div>

      {/* ── Main content: packet list + side panel ───────── */}
      <div className="flex gap-4 flex-1 min-h-0">

        {/* Packet List (Wireshark-style) */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Column headers */}
          <div className="grid text-xs text-gray-500 font-bold uppercase tracking-wider border-b border-gray-800 pb-1.5 px-2"
            style={{ gridTemplateColumns: "52px 80px 140px 140px 70px 50px 1fr" }}>
            <span>No.</span><span>Time</span><span>Source</span>
            <span>Destination</span><span>Protocol</span><span>Len</span><span>Info</span>
          </div>

          {/* Scrollable rows */}
          <div ref={tableRef} className="flex-1 overflow-y-auto min-h-0 space-y-px"
            style={{ maxHeight: "380px" }}>
            {packets.length === 0 ? (
              <div className="text-center text-gray-600 text-sm py-16">
                {capturing ? "Waiting for packets…" : "Click \"Start Capture\" to begin."}
              </div>
            ) : (
              packets.map((p) => (
                <div key={p.no}
                  onClick={() => setSelPkt(p)}
                  className={`grid text-xs font-mono px-2 py-0.5 cursor-pointer rounded
                    border-l-2 transition-colors
                    ${selPkt?.no === p.no ? "bg-cyan-900/30 border-l-cyan-400" : protoStyle(p.proto, p.suspicious)}
                    ${p.suspicious ? "border-l-red-500" : "border-l-transparent"}
                    hover:brightness-125`}
                  style={{ gridTemplateColumns: "52px 80px 140px 140px 70px 50px 1fr" }}>
                  <span className="text-gray-500">{p.no}</span>
                  <span className="text-gray-400">{p.time.toFixed(3)}</span>
                  <span className="truncate">{p.src || "—"}</span>
                  <span className="truncate">{p.dst || "—"}</span>
                  <span className={`font-bold ${p.suspicious ? "text-red-400" : ""}`}>{p.proto}</span>
                  <span className="text-gray-400">{p.len}</span>
                  <span className="truncate text-gray-300">{p.info}</span>
                </div>
              ))
            )}
          </div>

          {/* Packet detail */}
          {selPkt && (
            <div className="mt-3 bg-gray-900 border border-gray-700 rounded-xl p-4">
              <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Packet #{selPkt.no} Detail</p>
              <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs font-mono">
                {[
                  ["Time (relative)", selPkt.time.toFixed(6) + " s"],
                  ["Source IP",       selPkt.src || "—"],
                  ["Destination IP",  selPkt.dst || "—"],
                  ["Protocol",        selPkt.proto],
                  ["Length",          selPkt.len + " bytes"],
                  ["Info",            selPkt.info || "—"],
                  ["Suspicious",      selPkt.suspicious ? "⚠ YES" : "No"],
                ].map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="text-gray-500 shrink-0 w-32">{k}</span>
                    <span className={`text-gray-200 truncate ${k === "Suspicious" && selPkt.suspicious ? "text-red-400 font-bold" : ""}`}>{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* ── Side panel ──────────────────────────────────── */}
        <div className="w-72 shrink-0 flex flex-col gap-4">

          {/* Protocol stats */}
          <div className="bg-gray-900 border border-gray-700 rounded-xl p-4">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Protocol Stats</h3>
            {protoStats.length === 0 ? (
              <p className="text-gray-600 text-xs text-center py-4">No data yet</p>
            ) : (
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={protoStats} margin={{ left: -20 }}>
                  <XAxis dataKey="name" tick={{ fill: "#6b7280", fontSize: 9 }} />
                  <YAxis tick={{ fill: "#6b7280", fontSize: 9 }} />
                  <Tooltip contentStyle={{ background: "#1f2937", border: "1px solid #374151", color: "#e5e7eb", fontSize: 11 }} />
                  <Bar dataKey="count" fill="#06b6d4" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Alerts */}
          <div className="bg-gray-900 border border-orange-900 rounded-xl p-4 flex-1">
            <h3 className="text-xs font-bold text-orange-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <AlertTriangle size={13} />
              Live Alerts
              {alerts.length > 0 && (
                <span className="ml-auto bg-red-900 text-red-300 text-xs px-1.5 py-0.5 rounded-full font-bold">
                  {alerts.length}
                </span>
              )}
            </h3>
            <div className="space-y-2 overflow-y-auto" style={{ maxHeight: "300px" }}>
              {alerts.length === 0 ? (
                <div className="flex flex-col items-center py-6 text-gray-600">
                  <Shield size={24} className="mb-2 opacity-30" />
                  <p className="text-xs">No alerts yet</p>
                </div>
              ) : (
                alerts.map((a, i) => (
                  <div key={i} className="bg-red-950/40 border border-red-900/50 rounded-lg p-2.5">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-red-300 text-xs font-bold">#{a.no} {a.proto}</span>
                      {!saved.has(a.src) ? (
                        <button onClick={() => saveIOC(a)}
                          className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300">
                          <PlusCircle size={11} /> Save IOC
                        </button>
                      ) : (
                        <span className="flex items-center gap-1 text-xs text-green-400">
                          <CheckCircle size={11} /> Saved
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-400 font-mono truncate">{a.src} → {a.dst}</p>
                    <p className="text-xs text-gray-500 mt-0.5 truncate">{a.info}</p>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
