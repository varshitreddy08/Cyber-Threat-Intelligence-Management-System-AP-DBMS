import { NextResponse } from "next/server";
import { query } from "@/lib/db";

export async function GET() {
  try {
    const [dashboard] = await query("SELECT * FROM vw_dashboard");

    const severityStats = await query(
      `SELECT indicator_type, severity, total_count, malicious_count
       FROM vw_severity_stats ORDER BY indicator_type,
       CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3 ELSE 4 END`
    );

    const recentIndicators = await query(
      `SELECT indicator_id, indicator_type, indicator_value, severity, status,
              confidence_score, is_malicious, created_at
       FROM indicators ORDER BY created_at DESC LIMIT 10`
    );

    const recentIncidents = await query(
      `SELECT incident_id, incident_title, severity, status, discovered_at
       FROM incidents ORDER BY discovered_at DESC LIMIT 5`
    );

    const typeBreakdown = await query(
      `SELECT indicator_type AS name, COUNT(*) AS value
       FROM indicators WHERE is_malicious = TRUE
       GROUP BY indicator_type`
    );

    const actorActivity = await query(
      `SELECT actor_name AS name, total_indicators AS value
       FROM vw_actor_summary ORDER BY total_indicators DESC LIMIT 6`
    );

    return NextResponse.json({
      dashboard,
      severityStats,
      recentIndicators,
      recentIncidents,
      typeBreakdown,
      actorActivity,
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    return NextResponse.json({ error: msg }, { status: 500 });
  }
}
