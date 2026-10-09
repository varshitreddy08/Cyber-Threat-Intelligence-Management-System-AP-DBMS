import type { Metadata } from "next";
import "./globals.css";
import ClientWrapper from "@/components/ClientWrapper";

export const metadata: Metadata = {
  title: "CTIMS — Cyber Threat Intelligence",
  description: "Cyber Threat Intelligence Management System — Amrita Vishwa Vidyapeetham",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="h-full">
      <body className="min-h-full bg-[#0a0e1a] text-gray-100">
        <ClientWrapper>{children}</ClientWrapper>
      </body>
    </html>
  );
}
