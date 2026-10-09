-- ============================================================
--  CTIMS: Views
--  Covers: CREATE VIEW, JOIN types (INNER, LEFT, RIGHT),
--          Aggregate functions, GROUP BY, HAVING, ORDER BY,
--          CASE expressions, Subqueries, Window functions
-- ============================================================

-- ============================================================
--  VIEW 1: Active malicious indicators (INNER JOIN + CASE)
-- ============================================================
CREATE OR REPLACE VIEW vw_active_threats AS
SELECT
    i.indicator_id,
    i.indicator_type,
    i.indicator_value,
    i.severity,
    i.confidence_score,
    i.is_malicious,
    -- CASE expression to label risk level
    CASE
        WHEN i.confidence_score >= 90 THEN 'Confirmed'
        WHEN i.confidence_score >= 70 THEN 'Probable'
        WHEN i.confidence_score >= 50 THEN 'Suspected'
        ELSE 'Unknown'
    END AS confidence_label,
    ta.actor_name    AS threat_actor,
    ta.actor_type,
    ta.origin_country,
    u.username       AS reported_by,
    i.first_seen,
    i.last_seen
FROM indicators i
    INNER JOIN threat_actors ta ON i.actor_id = ta.actor_id   -- INNER JOIN
    INNER JOIN ctims_users   u  ON i.reported_by = u.user_id
WHERE i.status = 'Active'
  AND i.is_malicious = TRUE
ORDER BY
    CASE i.severity
        WHEN 'Critical' THEN 1
        WHEN 'High'     THEN 2
        WHEN 'Medium'   THEN 3
        WHEN 'Low'      THEN 4
    END;

-- ============================================================
--  VIEW 2: ALL indicators including those without actors
--          (LEFT JOIN — keeps indicators without actor assigned)
-- ============================================================
CREATE OR REPLACE VIEW vw_all_indicators AS
SELECT
    i.indicator_id,
    i.indicator_type,
    i.indicator_value,
    i.severity,
    i.status,
    i.is_malicious,
    i.confidence_score,
    COALESCE(ta.actor_name, 'Unknown Actor') AS threat_actor,
    COALESCE(ta.actor_type, 'N/A')           AS actor_type,
    COALESCE(u.username,    'System')        AS reported_by,
    i.first_seen,
    i.last_seen
FROM indicators i
    LEFT JOIN threat_actors ta ON i.actor_id   = ta.actor_id   -- LEFT JOIN
    LEFT JOIN ctims_users   u  ON i.reported_by = u.user_id;

-- ============================================================
--  VIEW 3: Threat Actor Summary
--          (GROUP BY, COUNT, MAX, AVG aggregate functions)
-- ============================================================
CREATE OR REPLACE VIEW vw_actor_summary AS
SELECT
    ta.actor_id,
    ta.actor_name,
    ta.actor_type,
    ta.origin_country,
    ta.sophistication_level,
    ta.active,
    COUNT(DISTINCT i.indicator_id)  AS total_indicators,
    COUNT(DISTINCT i.indicator_id)
        FILTER (WHERE i.indicator_type = 'IP')     AS ip_count,
    COUNT(DISTINCT i.indicator_id)
        FILTER (WHERE i.indicator_type = 'Domain') AS domain_count,
    COUNT(DISTINCT i.indicator_id)
        FILTER (WHERE i.indicator_type = 'URL')    AS url_count,
    COUNT(DISTINCT i.indicator_id)
        FILTER (WHERE i.indicator_type = 'Hash')   AS hash_count,
    COUNT(DISTINCT inc.incident_id) AS incident_count,
    ROUND(AVG(i.confidence_score), 1) AS avg_confidence,
    MAX(i.last_seen)                AS last_activity
FROM threat_actors ta
    LEFT JOIN indicators i   ON ta.actor_id = i.actor_id
    LEFT JOIN incidents  inc ON ta.actor_id = inc.actor_id
GROUP BY ta.actor_id, ta.actor_name, ta.actor_type,
         ta.origin_country, ta.sophistication_level, ta.active
ORDER BY total_indicators DESC;

-- ============================================================
--  VIEW 4: Severity statistics per indicator type
--          (GROUP BY, HAVING, CASE)
-- ============================================================
CREATE OR REPLACE VIEW vw_severity_stats AS
SELECT
    indicator_type,
    severity,
    COUNT(*)                                        AS total_count,
    COUNT(*) FILTER (WHERE is_malicious = TRUE)     AS malicious_count,
    COUNT(*) FILTER (WHERE status = 'Active')       AS active_count,
    ROUND(AVG(confidence_score), 2)                 AS avg_confidence,
    MIN(confidence_score)                           AS min_confidence,
    MAX(confidence_score)                           AS max_confidence,
    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical_count
FROM indicators
GROUP BY indicator_type, severity
HAVING COUNT(*) > 0
ORDER BY indicator_type,
    CASE severity
        WHEN 'Critical' THEN 1
        WHEN 'High'     THEN 2
        WHEN 'Medium'   THEN 3
        WHEN 'Low'      THEN 4
    END;

-- ============================================================
--  VIEW 5: Open incidents with actor + assignee details
--          (Multi-table JOIN, CASE, DISTINCT)
-- ============================================================
CREATE OR REPLACE VIEW vw_open_incidents AS
SELECT
    inc.incident_id,
    inc.incident_title,
    inc.severity,
    inc.status,
    inc.affected_systems,
    COALESCE(ta.actor_name, 'Unknown')   AS threat_actor,
    COALESCE(a.username,    'Unassigned') AS assigned_analyst,
    r.username                            AS reporter,
    inc.discovered_at,
    -- Age of incident
    EXTRACT(DAY FROM NOW() - inc.discovered_at)::INT AS open_days,
    -- SLA status using CASE
    CASE
        WHEN inc.severity = 'Critical' AND
             EXTRACT(HOUR FROM NOW() - inc.discovered_at) > 4   THEN 'SLA BREACH'
        WHEN inc.severity = 'High'    AND
             EXTRACT(DAY  FROM NOW() - inc.discovered_at) > 1   THEN 'SLA BREACH'
        WHEN inc.severity = 'Medium'  AND
             EXTRACT(DAY  FROM NOW() - inc.discovered_at) > 7   THEN 'SLA BREACH'
        ELSE 'On Track'
    END AS sla_status,
    COUNT(ii.indicator_id) AS linked_indicators
FROM incidents inc
    LEFT JOIN threat_actors  ta ON inc.actor_id    = ta.actor_id
    LEFT JOIN ctims_users     a ON inc.assigned_to = a.user_id
    LEFT JOIN ctims_users     r ON inc.reported_by = r.user_id
    LEFT JOIN incident_indicators ii ON inc.incident_id = ii.incident_id
WHERE inc.status NOT IN ('Closed','Resolved')
GROUP BY inc.incident_id, inc.incident_title, inc.severity, inc.status,
         inc.affected_systems, ta.actor_name, a.username, r.username,
         inc.discovered_at
ORDER BY
    CASE inc.severity
        WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
        WHEN 'Medium'   THEN 3 WHEN 'Low'  THEN 4
    END;

-- ============================================================
--  VIEW 6: Indicator ranking using Window Functions
--          (ROW_NUMBER, RANK, DENSE_RANK, LAG)
-- ============================================================
CREATE OR REPLACE VIEW vw_indicator_ranking AS
SELECT
    indicator_id,
    indicator_type,
    indicator_value,
    severity,
    confidence_score,
    is_malicious,
    first_seen,
    -- Row number within each indicator type
    ROW_NUMBER() OVER (
        PARTITION BY indicator_type
        ORDER BY confidence_score DESC
    ) AS rank_in_type,
    -- Rank with gaps for ties
    RANK() OVER (
        ORDER BY confidence_score DESC
    ) AS overall_rank,
    -- Percentage of confidence relative to max in its type
    ROUND(
        confidence_score * 100.0 /
        MAX(confidence_score) OVER (PARTITION BY indicator_type), 1
    ) AS pct_of_max,
    -- Previous indicator's confidence score
    LAG(confidence_score) OVER (
        PARTITION BY indicator_type
        ORDER BY first_seen
    ) AS prev_confidence,
    -- Running total confidence by type
    SUM(confidence_score) OVER (
        PARTITION BY indicator_type
        ORDER BY first_seen
        ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
    ) AS running_total
FROM indicators
WHERE is_malicious = TRUE;

-- ============================================================
--  VIEW 7: Dashboard summary (Subquery + Aggregation)
-- ============================================================
CREATE OR REPLACE VIEW vw_dashboard AS
SELECT
    (SELECT COUNT(*) FROM indicators WHERE status = 'Active')           AS active_indicators,
    (SELECT COUNT(*) FROM indicators WHERE severity = 'Critical')       AS critical_indicators,
    (SELECT COUNT(*) FROM threat_actors WHERE active = TRUE)            AS active_actors,
    (SELECT COUNT(*) FROM incidents WHERE status = 'Open')              AS open_incidents,
    (SELECT COUNT(*) FROM incidents WHERE status = 'In Progress')       AS inprogress_incidents,
    (SELECT COUNT(*) FROM vulnerabilities WHERE is_patched = FALSE)     AS unpatched_vulns,
    (SELECT COUNT(*) FROM malware)                                      AS total_malware,
    -- Subquery: actor with most indicators
    (SELECT actor_name FROM threat_actors ta
     JOIN indicators i ON ta.actor_id = i.actor_id
     GROUP BY ta.actor_name
     ORDER BY COUNT(*) DESC LIMIT 1)                                    AS most_active_actor,
    -- Average confidence across all indicators
    (SELECT ROUND(AVG(confidence_score),1) FROM indicators)             AS avg_confidence;

SELECT 'Views created successfully!' AS status;
