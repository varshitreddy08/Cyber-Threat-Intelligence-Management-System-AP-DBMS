import { NextRequest, NextResponse } from "next/server";
import { query } from "@/lib/db";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const type = searchParams.get("type");
  const severity = searchParams.get("severity");

  let sql = `SELECT i.indicator_id, i.indicator_type, i.indicator_value,
               i.severity, i.status, i.confidence_score, i.is_malicious,
               i.context, i.created_at,
               COALESCE(ta.actor_name,'Unknown') AS actor
             FROM indicators i
             LEFT JOIN threat_actors ta ON i.actor_id = ta.actor_id
             WHERE 1=1`;

  const params: string[] = [];
  let idx = 1;
  if (type && type !== "all")     { sql += ` AND i.indicator_type = $${idx++}`; params.push(type); }
  if (severity && severity !== "all") { sql += ` AND i.severity = $${idx++}`; params.push(severity); }

  sql += ` ORDER BY CASE i.severity
    WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END,
    i.created_at DESC LIMIT 100`;

  try {
    const rows = await query(sql, params);
    return NextResponse.json(rows);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { indicator_type, indicator_value, severity, is_malicious,
            confidence_score, context, actor_id } = body;

    const actorRef = actor_id ? actor_id : null;
    const [row] = await query(
      `INSERT INTO indicators (indicator_type, indicator_value, severity, status,
         is_malicious, confidence_score, context, actor_id, reported_by)
       VALUES ($1,$2,$3,'Active',$4,$5,$6,$7,1) RETURNING indicator_id`,
      [indicator_type, indicator_value, severity,
       is_malicious ?? true, confidence_score ?? 70,
       context ?? '', actorRef]
    );
    return NextResponse.json({ success: true, id: row.indicator_id });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
