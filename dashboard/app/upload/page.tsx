"use client";
import { useState, useCallback } from "react";
import { Upload, FileSearch, AlertTriangle, CheckCircle, PlusCircle, Wifi } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

interface SuggestedIOC { type: string; value: string; count: number; severity: string; reason: string; }
interface Suspicious   { type: string; detail: string; severity: string; }
interface Analysis {
  total_packets: number;
  top_source_ips: { ip: string; count: number }[];
  top_dest_ips:   { ip: string; count: number }[];
  protocol_breakdown: { name: string; count: number }[];
  top_ports:      { port: number; count: number }[];
  dns_queries:    string[];
  http_hosts:     string[];
  suspicious_activity: Suspicious[];
  suggested_iocs: SuggestedIOC[];
}

export default function UploadPage() {
  const [dragging, setDragging]   = useState(false);
  const [file, setFile]           = useState<File | null>(null);
  const [loading, setLoading]     = useState(false);
  const [result, setResult]       = useState<Analysis | null>(null);
  const [error, setError]         = useState("");
  const [saved, setSaved]         = useState<Set<string>>(new Set());
  const [saving, setSaving]       = useState<string>("");

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files[0];
    if (f) setFile(f);
  }, []);

  const analyze = async () => {
    if (!file) return;
    setLoading(true); setError(""); setResult(null);
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetch("/api/analyze-pcap", { method: "POST", body: form });
      const data = await res.json();
      if (data.error) setError(data.error);
      else setResult(data.analysis);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  };

  const saveIOC = async (ioc: SuggestedIOC) => {
    setSaving(ioc.value);
    try {
      const res = await fetch("/api/indicators", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          indicator_type:  ioc.type,
          indicator_value: ioc.value,
          severity:        ioc.severity,
          is_malicious:    true,
          confidence_score: 65,
          context: `Auto-detected from PCAP: ${ioc.reason}`,
        }),
      });
      const data = await res.json();
      if (data.success) setSaved(p => new Set([...p, ioc.value]));
      else setError(data.error);
    } finally {
      setSaving("");
    }
  };

  const severityColor = (s: string) => ({
    Critical:"text-red-400", High:"text-orange-400", Medium:"text-yellow-400", Low:"text-green-400"
  }[s] ?? "text-gray-400");

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-cyan-400">Upload & Analyze</h1>
        <p className="text-gray-500 text-sm mt-1">Upload a Wireshark PCAP file to extract threat intelligence automatically.</p>
      </div>

      {/* Upload Zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`border-2 border-dashed rounded-xl p-12 text-center transition-all cursor-pointer
          ${dragging ? "border-cyan-400 bg-cyan-900/10" : "border-gray-700 hover:border-gray-500"}`}
        onClick={() => document.getElementById("file-input")?.click()}>
        <input id="file-input" type="file" accept=".pcap,.pcapng,.cap" className="hidden"
          onChange={e => setFile(e.target.files?.[0] ?? null)} />
        <Upload className="mx-auto text-gray-500 mb-3" size={40} />
        {file ? (
          <div>
            <p className="text-cyan-300 font-bold text-lg">{file.name}</p>
            <p className="text-gray-500 text-sm mt-1">{(file.size / 1024).toFixed(1)} KB · Click to change</p>
          </div>
        ) : (
          <div>
            <p className="text-gray-300 text-lg">Drop your Wireshark PCAP file here</p>
            <p className="text-gray-600 text-sm mt-1">Supports .pcap · .pcapng · .cap</p>
          </div>
        )}
      </div>

      {file && !loading && (
        <button onClick={analyze}
          className="flex items-center gap-2 bg-cyan-700 hover:bg-cyan-600 text-white px-6 py-3 rounded-xl font-bold transition-colors">
          <FileSearch size={18} /> Analyze with Wireshark (tshark)
        </button>
      )}

      {loading && (
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6 text-center">
          <Wifi className="mx-auto text-cyan-400 animate-pulse mb-2" size={32} />
          <p className="text-cyan-300">Analyzing packets with tshark...</p>
          <p className="text-gray-500 text-sm mt-1">Extracting IPs, protocols, DNS queries, suspicious traffic</p>
        </div>
      )}

      {error && (
        <div className="bg-red-950 border border-red-800 rounded-xl p-4 flex items-center gap-3">
          <AlertTriangle className="text-red-400 shrink-0" size={20} />
          <p className="text-red-300 text-sm">{error}</p>
        </div>
      )}

      {result && (
        <div className="space-y-5">
          {/* Summary */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: "Total Packets",       value: result.total_packets },
              { label: "Unique Source IPs",   value: result.top_source_ips.length },
              { label: "Suspicious Events",   value: result.suspicious_activity.length },
              { label: "Suggested IOCs",      value: result.suggested_iocs.length },
            ].map(({ label, value }) => (
              <div key={label} className="bg-gray-900 border border-gray-700 rounded-xl p-4 text-center">
                <p className="text-2xl font-bold text-cyan-400">{value}</p>
                <p className="text-gray-500 text-xs mt-1">{label}</p>
              </div>
            ))}
          </div>

          {/* Protocol Chart */}
          {result.protocol_breakdown.length > 0 && (
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
              <h2 className="text-sm font-bold text-gray-300 mb-4 uppercase tracking-wider">Protocol Breakdown</h2>
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={result.protocol_breakdown} margin={{ left:-10 }}>
                  <XAxis dataKey="name" tick={{ fill:"#9ca3af", fontSize:10 }} />
                  <YAxis tick={{ fill:"#9ca3af", fontSize:10 }} />
                  <Tooltip contentStyle={{ background:"#1f2937", border:"1px solid #374151", color:"#e5e7eb" }} />
                  <Bar dataKey="count" fill="#06b6d4" radius={[4,4,0,0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Two-column: Top IPs */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
              <h2 className="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wider">Top Source IPs</h2>
              <table className="w-full text-sm">
                <thead><tr className="text-gray-500 text-xs"><th className="text-left py-1">IP</th><th className="text-right">Packets</th></tr></thead>
                <tbody>
                  {result.top_source_ips.map(({ ip, count }) => (
                    <tr key={ip} className="border-t border-gray-800">
                      <td className="py-1.5 font-mono text-gray-300">{ip}</td>
                      <td className="text-right text-cyan-400">{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
              <h2 className="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wider">Top Destination IPs</h2>
              <table className="w-full text-sm">
                <thead><tr className="text-gray-500 text-xs"><th className="text-left py-1">IP</th><th className="text-right">Packets</th></tr></thead>
                <tbody>
                  {result.top_dest_ips.map(({ ip, count }) => (
                    <tr key={ip} className="border-t border-gray-800">
                      <td className="py-1.5 font-mono text-gray-300">{ip}</td>
                      <td className="text-right text-cyan-400">{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Suspicious Activity */}
          {result.suspicious_activity.length > 0 && (
            <div className="bg-gray-900 border border-orange-900 rounded-xl p-5">
              <h2 className="text-sm font-bold text-orange-300 mb-3 uppercase tracking-wider flex items-center gap-2">
                <AlertTriangle size={16} /> Suspicious Activity Detected
              </h2>
              <div className="space-y-2">
                {result.suspicious_activity.map((s, i) => (
                  <div key={i} className="flex items-start gap-3 py-2 border-b border-gray-800 last:border-0">
                    <span className={`text-xs font-bold mt-0.5 ${severityColor(s.severity)}`}>[{s.severity}]</span>
                    <div>
                      <p className="text-xs text-gray-400 font-bold">{s.type}</p>
                      <p className="text-sm text-gray-200">{s.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* DNS Queries */}
          {result.dns_queries.length > 0 && (
            <div className="bg-gray-900 border border-gray-700 rounded-xl p-5">
              <h2 className="text-sm font-bold text-gray-300 mb-3 uppercase tracking-wider">DNS Queries Observed</h2>
              <div className="flex flex-wrap gap-2">
                {result.dns_queries.map(d => (
                  <span key={d} className="bg-gray-800 text-gray-300 text-xs font-mono px-2 py-1 rounded">{d}</span>
                ))}
              </div>
            </div>
          )}

          {/* Suggested IOCs */}
          {result.suggested_iocs.length > 0 && (
            <div className="bg-gray-900 border border-cyan-900 rounded-xl p-5">
              <h2 className="text-sm font-bold text-cyan-300 mb-3 uppercase tracking-wider flex items-center gap-2">
                <PlusCircle size={16} /> Suggested IOCs — Save to Database
              </h2>
              <p className="text-gray-500 text-xs mb-4">Click &quot;Save&quot; to add these to your CTIMS indicator database. Triggers will fire automatically.</p>
              <div className="space-y-3">
                {result.suggested_iocs.map((ioc) => (
                  <div key={ioc.value} className="flex items-center justify-between bg-gray-800 rounded-lg px-4 py-3">
                    <div>
                      <span className="text-xs text-gray-500 mr-2">[{ioc.type}]</span>
                      <span className="font-mono text-gray-200 text-sm">{ioc.value}</span>
                      <p className="text-xs text-gray-500 mt-0.5">{ioc.reason}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`text-xs font-bold ${severityColor(ioc.severity)}`}>{ioc.severity}</span>
                      {saved.has(ioc.value) ? (
                        <span className="flex items-center gap-1 text-green-400 text-xs font-bold">
                          <CheckCircle size={14} /> Saved
                        </span>
                      ) : (
                        <button onClick={() => saveIOC(ioc)}
                          disabled={saving === ioc.value}
                          className="bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-xs px-3 py-1.5 rounded-lg font-bold transition-colors">
                          {saving === ioc.value ? "Saving…" : "Save to DB"}
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
