"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Eye, EyeOff, LogIn } from "lucide-react";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw,   setShowPw]   = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail ?? "Invalid username or password");
        return;
      }
      localStorage.setItem("ctims_user", JSON.stringify(data.user));
      const role = (data.user.role ?? "").toLowerCase();
      router.push(role === "admin" ? "/admin" : "/analyst");
    } catch {
      setError("Cannot connect to CTIMS server. Is FastAPI running on port 8000?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center"
      style={{ background: "#0b0e14" }}>
      <div className="w-full max-w-md">

        {/* Logo */}
        <div className="text-center mb-10">
          <div className="inline-flex p-3 rounded-2xl mb-4"
            style={{ background: "#1e2a3a", boxShadow: "0 0 24px rgba(101,163,13,0.35)" }}>
            <Shield size={40} style={{ color: "#65a30d" }} />
          </div>
          <h1 className="text-3xl font-bold tracking-[0.2em]" style={{ color: "#65a30d" }}>CTIMS</h1>
          <p className="text-gray-500 text-sm mt-1">Cyber Threat Intelligence Management System</p>
          <p className="text-gray-600 text-xs mt-1">Amrita Vishwa Vidyapeetham · Advanced Programming &amp; Database Management System</p>
        </div>

        {/* Card */}
        <div className="rounded-2xl p-8" style={{ background: "#171d2b", border: "1px solid #1e2a3a" }}>
          <h2 className="text-lg font-bold text-gray-200 mb-6">Sign in to your account</h2>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="text-xs text-gray-500 uppercase tracking-wider">Username</label>
              <input
                value={username}
                onChange={e => setUsername(e.target.value)}
                required autoFocus
                className="mt-1 w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 text-gray-200 text-sm focus:outline-none focus:border-cyan-600 font-mono"
                placeholder="Enter username"
              />
            </div>

            <div>
              <label className="text-xs text-gray-500 uppercase tracking-wider">Password</label>
              <div className="relative mt-1">
                <input
                  type={showPw ? "text" : "password"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 pr-10 text-gray-200 text-sm focus:outline-none focus:border-cyan-600 font-mono"
                  placeholder="••••••••"
                />
                <button type="button" onClick={() => setShowPw(!showPw)}
                  className="absolute right-3 top-3 text-gray-500 hover:text-gray-300">
                  {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="bg-red-950 border border-red-800 rounded-lg px-4 py-2.5 text-red-300 text-sm">
                {error}
              </div>
            )}

            <button type="submit" disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-sm transition-all disabled:opacity-50"
              style={{ background: loading ? "#374151" : "#65a30d", color: "#000" }}>
              <LogIn size={16} />
              {loading ? "Signing in…" : "Sign In"}
            </button>
          </form>
        </div>

        <p className="text-center text-gray-700 text-xs mt-6">
          P VARSHITH REDDY · A ROHAN KARTHIK REDDY · Supervisors: Dr. S.Saravanan · Dr. G.Saranya
        </p>
      </div>
    </div>
  );
}
