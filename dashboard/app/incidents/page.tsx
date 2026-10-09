"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function IncidentsPage() {
  const router = useRouter();
  useEffect(() => {
    const raw = localStorage.getItem("ctims_user");
    if (!raw) { router.replace("/login"); return; }
    const role = (JSON.parse(raw).role ?? "").toLowerCase();
    router.replace(role === "admin" ? "/admin" : "/analyst");
  }, [router]);
  return null;
}
