"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Shield, Upload, Radio, BookOpen, ArrowLeft } from "lucide-react";

const NAV = [
  { href: "/upload",  label: "PCAP Analysis",   icon: Upload   },
  { href: "/capture", label: "Live Capture",     icon: Radio    },
  { href: "/about",   label: "Project Overview", icon: BookOpen },
];

export default function Sidebar() {
  const path   = usePathname();
  const router = useRouter();

  const goBack = () => {
    try {
      const raw  = localStorage.getItem("ctims_user");
      const role = raw ? (JSON.parse(raw).role ?? "").toLowerCase() : "";
      router.push(role === "admin" ? "/admin" : "/analyst");
    } catch {
      router.push("/login");
    }
  };

  return (
    <aside className="fixed top-0 left-0 h-full w-64 flex flex-col z-10"
      style={{ background: "#0b0e14", borderRight: "1px solid #1e2a3a" }}>

      {/* Logo */}
      <div className="p-5" style={{ borderBottom: "1px solid #1e2a3a" }}>
        <div className="flex items-center gap-3">
          <div className="p-1.5 rounded-lg" style={{ background: "#1e2a3a", boxShadow: "0 0 12px rgba(101,163,13,0.4)" }}>
            <Shield size={22} style={{ color: "#65a30d" }} />
          </div>
          <div>
            <p className="font-bold text-sm tracking-[0.2em]" style={{ color: "#65a30d" }}>CTIMS</p>
            <p className="text-xs" style={{ color: "#4b5563" }}>Threat Intelligence</p>
          </div>
        </div>
        <p className="text-xs mt-3 leading-4" style={{ color: "#374151" }}>
          Amrita Vishwa Vidyapeetham<br />Advanced Programming &amp; DBMS
        </p>
      </div>

      {/* Back to Dashboard */}
      <div className="px-3 pt-3">
        <button onClick={goBack}
          className="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm transition-all"
          style={{ color: "#65a30d", border: "1px solid rgba(101,163,13,0.25)", background: "rgba(101,163,13,0.08)" }}>
          <ArrowLeft size={15} />
          Back to Dashboard
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1 mt-1">
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = path === href;
          return (
            <Link key={href} href={href}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all"
              style={active
                ? { background: "rgba(101,163,13,0.15)", color: "#84cc16", border: "1px solid rgba(101,163,13,0.3)" }
                : { color: "#6b7280", border: "1px solid transparent" }}>
              <Icon size={15} />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-4 text-xs" style={{ borderTop: "1px solid #1e2a3a", color: "#374151" }}>
        <p className="font-bold" style={{ color: "#4b5563" }}>P VARSHITH REDDY</p>
        <p>CH.SC.U4CYS25022</p>
        <p className="font-bold mt-1" style={{ color: "#4b5563" }}>A ROHAN KARTHIK REDDY</p>
        <p>CH.SC.Y4CYS25002</p>
      </div>
    </aside>
  );
}
