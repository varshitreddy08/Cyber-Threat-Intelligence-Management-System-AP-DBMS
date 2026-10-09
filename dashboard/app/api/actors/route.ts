import { NextResponse } from "next/server";
import { query } from "@/lib/db";

export async function GET() {
  try {
    const rows = await query("SELECT * FROM vw_actor_summary ORDER BY total_indicators DESC");
    return NextResponse.json(rows);
  } catch (e: unknown) {
    return NextResponse.json({ error: e instanceof Error ? e.message : String(e) }, { status: 500 });
  }
}
