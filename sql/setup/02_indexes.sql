-- ============================================================
--  CTIMS: Indexes
--  Covers: CREATE INDEX, CREATE UNIQUE INDEX, DROP INDEX
--  Purpose: Speed up SELECT queries on frequently filtered columns
-- ============================================================

-- ============================================================
--  Indexes on indicators table
-- ============================================================

-- B-Tree index on indicator_type (used in WHERE indicator_type = 'IP')
CREATE INDEX idx_indicators_type
    ON indicators(indicator_type);

-- B-Tree index on severity (WHERE severity = 'Critical')
CREATE INDEX idx_indicators_severity
    ON indicators(severity);

-- Index on status (WHERE status = 'Active')
CREATE INDEX idx_indicators_status
    ON indicators(status);

-- Index on actor_id (JOIN and WHERE)
CREATE INDEX idx_indicators_actor
    ON indicators(actor_id);

-- Index on reported_by (JOIN with users)
CREATE INDEX idx_indicators_reporter
    ON indicators(reported_by);

-- Index on first_seen (range queries: date filtering)
CREATE INDEX idx_indicators_first_seen
    ON indicators(first_seen DESC);

-- Composite index for common filter combination
CREATE INDEX idx_indicators_type_severity
    ON indicators(indicator_type, severity);

-- ============================================================
--  Indexes on threat_actors table
-- ============================================================
CREATE INDEX idx_actors_type
    ON threat_actors(actor_type);

CREATE INDEX idx_actors_country
    ON threat_actors(origin_country);

CREATE INDEX idx_actors_sophistication
    ON threat_actors(sophistication_level DESC);

-- ============================================================
--  Indexes on incidents table
-- ============================================================
CREATE INDEX idx_incidents_status
    ON incidents(status);

CREATE INDEX idx_incidents_severity
    ON incidents(severity);

CREATE INDEX idx_incidents_assigned
    ON incidents(assigned_to);

CREATE INDEX idx_incidents_discovered
    ON incidents(discovered_at DESC);

-- ============================================================
--  Indexes on malware table
-- ============================================================
CREATE INDEX idx_malware_type
    ON malware(malware_type);

CREATE INDEX idx_malware_severity
    ON malware(severity_score DESC);

-- ============================================================
--  Indexes on vulnerabilities table
-- ============================================================
CREATE UNIQUE INDEX idx_vuln_cve
    ON vulnerabilities(cve_id)
    WHERE cve_id IS NOT NULL;       -- Partial unique index

CREATE INDEX idx_vuln_cvss
    ON vulnerabilities(cvss_score DESC);

CREATE INDEX idx_vuln_unpatched
    ON vulnerabilities(is_patched)
    WHERE is_patched = FALSE;       -- Partial index for unpatched only

-- ============================================================
--  Indexes on audit_log
-- ============================================================
CREATE INDEX idx_audit_table_op
    ON audit_log(table_name, operation);

CREATE INDEX idx_audit_performed_at
    ON audit_log(performed_at DESC);

-- ============================================================
--  Demo: View index usage plan
-- ============================================================
-- EXPLAIN ANALYZE SELECT * FROM indicators WHERE indicator_type = 'IP' AND severity = 'Critical';

SELECT 'Indexes created successfully!' AS status;
