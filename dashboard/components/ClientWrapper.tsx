"use client";
import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import Sidebar from "./Sidebar";

// Pages that render their own full-screen layout (no sidebar, no auth guard here)
const STANDALONE = ["/", "/login", "/admin", "/analyst"];

export default function ClientWrapper({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router   = useRouter();

  const isStandalone = STANDALONE.some(p => pathname === p || pathname.startsWith(p + "/"));

  useEffect(() => {
    if (isStandalone) return;
    // Protected routes — require login
    const raw = localStorage.getItem("ctims_user");
    if (!raw) {
      router.replace("/login");
    }
  }, [pathname, isStandalone, router]);

  if (isStandalone) {
    // Login / Admin / Analyst — full-screen, no sidebar
    return <>{children}</>;
  }

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 ml-64 p-6 overflow-auto">{children}</main>
    </div>
  );
}
