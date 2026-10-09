"use client";
import {
  Shield, AlertTriangle, Database, Search, GitBranch,
  FileText, Activity, Users, Lock, Cpu, Globe, CheckCircle2,
  BookOpen, Code2, Server, Layers
} from "lucide-react";

const PROBLEMS = [
  {
    icon: AlertTriangle,
    color: "text-red-400",
    bg: "bg-red-900/10 border-red-900",
    title: "Duplicate & Outdated Indicators",
    problem: "Indicators in separate files become duplicated and outdated with no single source of truth.",
    solution: "UNIQUE constraints prevent duplicates. Partial indexes flag stale entries. vw_active_threats filters current IOCs only.",
  },
  {
    icon: GitBranch,
    color: "text-orange-400",
    bg: "bg-orange-900/10 border-orange-900",
    title: "Disconnected Threat Entities",
    problem: "IPs, domains, malware, and incidents stored separately — no correlation possible.",
    solution: "Foreign keys link all entities. incident_indicators handles many-to-many. JOINs surface all connections instantly.",
  },
  {
    icon: Search,
    color: "text-yellow-400",
    bg: "bg-yellow-900/10 border-yellow-900",
    title: "No Efficient Search or Filtering",
    problem: "Analysts waste time manually searching files with no filter by severity or type.",
    solution: "B-tree indexes on indicator_type, severity, and actor_id. Dashboard live-filters with parameterized SQL.",
  },
  {
    icon: Database,
    color: "text-cyan-400",
    bg: "bg-cyan-900/10 border-cyan-900",
    title: "No Structured Historical Record",
    problem: "No audit trail. Changes go untracked. No record of who reported what or when.",
    solution: "trg_audit_indicators auto-logs every INSERT, UPDATE, DELETE on indicators to audit_log.",
  },
  {
    icon: FileText,
    color: "text-purple-400",
    bg: "bg-purple-900/10 border-purple-900",
    title: "No Severity Classification",
    problem: "All threats treated equally — critical zero-days and low-priority IPs get the same attention.",
    solution: "CHECK constraint enforces Critical/High/Medium/Low. trg_auto_incident_critical escalates Critical IOCs automatically.",
  },
  {
    icon: Users,
    color: "text-lime-400",
    bg: "bg-lime-900/10 border-lime-900",
    title: "No Role-Based Access",
    problem: "All analysts share the same permissions — no visibility into who changed what.",
    solution: "Roles enforced in Java (canAccess()) and dashboard routing. Admins manage accounts and audit log. Analysts submit IOCs only.",
  },
];

const TECH = [
  { icon: Code2,   color: "text-orange-400",  label: "Java 17", desc: "15 OOP classes — Abstract, Inheritance, Polymorphism, Singleton, Strategy, Comparable, Facade" },
  { icon: Database,  color: "text-cyan-400",   label: "Neon PostgreSQL", desc: "10 tables, 7 views, 15+ indexes, 5 triggers, 3 stored functions, window functions, CTEs" },
  { icon: Server,  color: "text-lime-400",    label: "FastAPI (Python)", desc: "Async REST API with asyncpg, WebSocket live updates, PCAP analysis via pyshark/tshark" },
  { icon: Globe,   color: "text-blue-400",    label: "Next.js 16", desc: "App Router, Turbopack, Recharts, Tailwind CSS — real-time dashboard with WebSocket" },
  { icon: Layers,  color: "text-purple-400",  label: "Wireshark / tshark", desc: "PCAP file analysis and live packet capture — protocol detection, IOC extraction" },
  { icon: Cpu,     color: "text-pink-400",    label: "Scapy", desc: "4 test PCAP files generated — C2 traffic, phishing DNS, port scan/DDoS, mixed threats" },
];

const OOP = [
  { concept: "Encapsulation",  where: "DatabaseManager, Indicator, User — private fields with public methods" },
  { concept: "Inheritance",    where: "IPIndicator, DomainIndicator, URLIndicator, HashIndicator → Indicator" },
  { concept: "Polymorphism",   where: "analyze() overridden in all 4 indicator subclasses; canAccess() in Admin vs Analyst" },
  { concept: "Abstraction",    where: "Abstract classes Indicator, User, ThreatAnalyzer hide implementation details" },
  { concept: "Singleton",      where: "DatabaseManager — single JDBC connection instance across the application" },
  { concept: "Strategy",       where: "BasicAnalyzer vs AdvancedAnalyzer swap analysis algorithms at runtime" },
  { concept: "Comparable",     where: "Indicator implements Comparable<Indicator> — sorted by severity score" },
  { concept: "Static Members", where: "Admin.adminCount tracks total admin instances across all objects" },
];

const SQL = [
  { feature: "DDL + Constraints",  desc: "NOT NULL, UNIQUE, CHECK, DEFAULT, GENERATED ALWAYS AS computed columns, ALTER TABLE" },
  { feature: "Indexes",             desc: "B-tree on type/severity, partial index for unpatched CVEs, composite indexes" },
  { feature: "Views (7)",           desc: "vw_active_threats, vw_all_indicators, vw_actor_summary, vw_severity_stats, vw_open_incidents, vw_indicator_ranking, vw_dashboard" },
  { feature: "Triggers (5)",        desc: "Auto audit log, auto-create incident for Critical IOC, prevent Critical delete, auto timestamp, actor audit" },
  { feature: "Stored Functions",    desc: "fn_indicator_risk_score(), fn_count_by_severity(), fn_high_activity_actors()" },
  { feature: "Window Functions",    desc: "ROW_NUMBER, RANK, LAG, running totals in vw_indicator_ranking" },
  { feature: "CTEs & Subqueries",   desc: "EXISTS, correlated subqueries, scalar subqueries, multi-level CTEs in reports" },
  { feature: "JOINs",               desc: "INNER, LEFT, RIGHT joins across all 10 tables demonstrated in views and reports" },
];

export default function AboutPage() {
  return (
    <div className="space-y-10 pb-10">

      {/* ── Header ─────────────────────────────────────────────── */}
      <div className="relative overflow-hidden rounded-2xl p-8"
        style={{ background: "linear-gradient(135deg, #0d1520 0%, #0b1a10 100%)", border: "1px solid #1e3a2a" }}>
        <div className="absolute top-0 right-0 w-64 h-64 opacity-5">
          <Shield size={256} style={{ color: "#65a30d" }} />
        </div>
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-xl" style={{ background: "#1e3a1a", boxShadow: "0 0 20px rgba(101,163,13,0.4)" }}>
              <Shield size={28} style={{ color: "#65a30d" }} />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-[0.15em]" style={{ color: "#65a30d" }}>CTIMS</h1>
              <p className="text-xs text-gray-500">Cyber Threat Intelligence Management System</p>
            </div>
          </div>
          <p className="text-gray-400 text-sm leading-relaxed max-w-3xl">
            Advanced Programming &amp; Database Management System · B.Tech II · Amrita Vishwa Vidyapeetham
          </p>
          <div className="flex gap-6 mt-5 text-xs text-gray-500">
            <div>
              <p className="font-bold text-gray-300">P VARSHITH REDDY</p>
              <p className="font-mono">CH.SC.U4CYS25022</p>
            </div>
            <div className="w-px bg-gray-800" />
            <div>
              <p className="font-bold text-gray-300">A ROHAN KARTHIK REDDY</p>
              <p className="font-mono">CH.SC.Y4CYS25002</p>
            </div>
            <div className="w-px bg-gray-800" />
            <div>
              <p className="text-gray-500">Supervisors</p>
              <p className="text-gray-300 font-bold">Dr. S. Saravanan</p>
              <p className="text-gray-300 font-bold">Dr. G.Saranya</p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Problem Statement ──────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <BookOpen size={16} className="text-cyan-400" />
          <h2 className="text-lg font-bold text-gray-200 uppercase tracking-wider">Problem Statement</h2>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-2xl p-6 space-y-3 text-base text-gray-400 leading-relaxed">
          <p>
            With the increasing number of cyberattacks, organizations generate and collect large amounts of
            threat-related information such as <span className="text-cyan-300">IP addresses, domains, URLs, file hashes,
            malware, vulnerabilities, threat actors, and security incidents.</span>
          </p>
          <p>
            Managing this information manually or through separate files creates several problems. Threat indicators
            may be <span className="text-orange-300">duplicated, outdated, difficult to search, or disconnected</span> from
            related incidents. Analysts may also find it difficult to determine whether an indicator is associated
            with a particular malware family, threat actor, vulnerability, or previous incident.
          </p>
          <p>
            Another major issue is the <span className="text-red-300">absence of a structured system for maintaining
            historical threat intelligence.</span> Without proper organization, analysts spend significant time
            searching and correlating information instead of analyzing threats.
          </p>
          <p className="text-gray-300 font-medium border-t border-gray-800 pt-3">
            Therefore, there is a need for a centralized Cyber Threat Intelligence Management System that can
            store threat information in a structured database, establish relationships between different entities,
            provide efficient searching and updating, classify threats based on severity, and generate reports.
          </p>
        </div>
      </div>

      {/* ── How CTIMS solves each problem ─────────────────────── */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <CheckCircle2 size={16} className="text-lime-400" />
          <h2 className="text-lg font-bold text-gray-200 uppercase tracking-wider">How CTIMS Solves It</h2>
        </div>
        <div className="grid grid-cols-2 gap-4">
          {PROBLEMS.map(({ icon: Icon, color, bg, title, problem, solution }) => (
            <div key={title} className={`rounded-xl border p-5 ${bg}`}>
              <div className="flex items-center gap-2 mb-3">
                <Icon size={16} className={color} />
                <h3 className="font-bold text-gray-200 text-sm">{title}</h3>
              </div>
              <p className="text-sm text-gray-500 leading-relaxed mb-2">
                <span className="text-gray-600 font-bold">Problem: </span>{problem}
              </p>
              <p className="text-sm text-gray-300 leading-relaxed">
                <span className={`font-bold ${color}`}>Solution: </span>{solution}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* ── Tech Stack ─────────────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Cpu size={16} className="text-purple-400" />
          <h2 className="text-lg font-bold text-gray-200 uppercase tracking-wider">Technology Stack</h2>
        </div>
        <div className="grid grid-cols-3 gap-3">
          {TECH.map(({ icon: Icon, color, label, desc }) => (
            <div key={label} className="bg-gray-900 border border-gray-700 rounded-xl p-4 hover:border-gray-600 transition-colors">
              <div className="flex items-center gap-2 mb-2">
                <Icon size={16} className={color} />
                <span className={`font-bold text-sm ${color}`}>{label}</span>
              </div>
              <p className="text-sm text-gray-500 leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── OOP Concepts ───────────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Code2 size={16} className="text-orange-400" />
          <h2 className="text-lg font-bold text-gray-200 uppercase tracking-wider">OOP Concepts Implemented</h2>
          <span className="text-xs text-gray-600 ml-2">Java · 15 classes across 13 source files</span>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                <th className="text-left px-5 py-3 w-40">Concept</th>
                <th className="text-left px-5 py-3">Where Used in CTIMS</th>
              </tr>
            </thead>
            <tbody>
              {OOP.map((r, i) => (
                <tr key={r.concept} className={`border-b border-gray-800 text-sm ${i % 2 === 0 ? "" : "bg-gray-800/20"}`}>
                  <td className="px-5 py-3 font-bold text-orange-400 font-mono">{r.concept}</td>
                  <td className="px-5 py-3 text-gray-300">{r.where}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Advanced SQL ───────────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Database size={16} className="text-cyan-400" />
          <h2 className="text-lg font-bold text-gray-200 uppercase tracking-wider">Advanced SQL Features</h2>
          <span className="text-xs text-gray-600 ml-2">PostgreSQL · Neon Serverless</span>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                <th className="text-left px-5 py-3 w-48">SQL Feature</th>
                <th className="text-left px-5 py-3">Implementation</th>
              </tr>
            </thead>
            <tbody>
              {SQL.map((r, i) => (
                <tr key={r.feature} className={`border-b border-gray-800 text-sm ${i % 2 === 0 ? "" : "bg-gray-800/20"}`}>
                  <td className="px-5 py-3 font-bold text-cyan-400 font-mono">{r.feature}</td>
                  <td className="px-5 py-3 text-gray-300">{r.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Architecture ───────────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Layers size={16} className="text-blue-400" />
          <h2 className="text-lg font-bold text-gray-200 uppercase tracking-wider">System Architecture</h2>
        </div>
        <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
          <div className="flex items-center justify-between gap-3 text-center text-xs">
            {[
              { label: "Java CLI",        sub: "OOP layer",        color: "bg-orange-900/40 border-orange-800 text-orange-300" },
              { label: "→", sub: "",      color: "bg-transparent border-transparent text-gray-600", nobox: true },
              { label: "FastAPI",         sub: "REST + WebSocket", color: "bg-lime-900/40 border-lime-800 text-lime-300" },
              { label: "⇄", sub: "",      color: "bg-transparent border-transparent text-gray-600", nobox: true },
              { label: "Neon PostgreSQL", sub: "10 tables · 7 views", color: "bg-cyan-900/40 border-cyan-800 text-cyan-300" },
              { label: "→", sub: "",      color: "bg-transparent border-transparent text-gray-600", nobox: true },
              { label: "Next.js 16",      sub: "Dashboard UI",     color: "bg-blue-900/40 border-blue-800 text-blue-300" },
              { label: "→", sub: "",      color: "bg-transparent border-transparent text-gray-600", nobox: true },
              { label: "Wireshark",       sub: "PCAP / Live",      color: "bg-purple-900/40 border-purple-800 text-purple-300" },
            ].map((item, i) => (
              item.nobox ? (
                <span key={i} className="text-lg text-gray-700 shrink-0">{item.label}</span>
              ) : (
                <div key={i} className={`flex-1 rounded-xl border py-3 px-2 ${item.color}`}>
                  <p className="font-bold">{item.label}</p>
                  {item.sub && <p className="opacity-60 mt-0.5 text-xs">{item.sub}</p>}
                </div>
              )
            ))}
          </div>
          <div className="mt-5 flex flex-wrap gap-2 justify-center text-xs">
            {[
              "JDBC (Java↔DB)","asyncpg (FastAPI↔DB)","pg Pool (Next.js↔DB)",
              "WebSocket (real-time push)","pyshark / tshark","Scapy (test PCAPs)",
            ].map(t => (
              <span key={t} className="bg-gray-800 text-gray-400 border border-gray-700 px-3 py-1 rounded-full">{t}</span>
            ))}
          </div>
        </div>
      </div>

    </div>
  );
}
