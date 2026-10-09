"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Shield } from "lucide-react";

export default function RootPage() {
  const router = useRouter();

  useEffect(() => {
    const raw = localStorage.getItem("ctims_user");
    if (!raw) {
      router.replace("/login");
      return;
    }
    try {
      const user = JSON.parse(raw);
      const role = (user.role ?? "").toLowerCase();
      router.replace(role === "admin" ? "/admin" : "/analyst");
    } catch {
      localStorage.removeItem("ctims_user");
      router.replace("/login");
    }
  }, [router]);

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "#0b0e14" }}>
      <div className="text-center">
        <div className="inline-flex p-3 rounded-2xl mb-4"
          style={{ background: "#1e2a3a", boxShadow: "0 0 24px rgba(101,163,13,0.35)" }}>
          <Shield size={36} style={{ color: "#65a30d" }} />
        </div>
        <p className="text-gray-500 text-sm animate-pulse">Redirecting…</p>
      </div>
    </div>
  );
}
