-- ============================================================
--  CTIMS: Triggers & PL/pgSQL Functions
--  Covers: AFTER INSERT, AFTER UPDATE, BEFORE DELETE triggers,
--          PL/pgSQL, IF/ELSIF/ELSE, NEW/OLD records,
--          Automatic audit logging, business rule enforcement
-- ============================================================

-- ============================================================
--  TRIGGER FUNCTION 1: Audit all indicator changes
--  Fires on: INSERT, UPDATE, DELETE on indicators
-- ============================================================
CREATE OR REPLACE FUNCTION fn_audit_indicators()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log (table_name, operation, record_id, new_data, performed_by)
        VALUES (
            'indicators',
            'INSERT',
            NEW.indicator_id,
            'Type=' || NEW.indicator_type ||
            ', Value=' || NEW.indicator_value ||
            ', Severity=' || NEW.severity ||
            ', Status=' || NEW.status,
            COALESCE(current_user, 'system')
        );

    ELSIF TG_OP = 'UPDATE' THEN
        -- Only log if meaningful fields changed
        IF OLD.status    <> NEW.status    OR
           OLD.severity  <> NEW.severity  OR
           OLD.is_malicious <> NEW.is_malicious THEN
            INSERT INTO audit_log (table_name, operation, record_id, old_data, new_data, performed_by)
            VALUES (
                'indicators',
                'UPDATE',
                NEW.indicator_id,
                'Status=' || OLD.status    || ', Severity=' || OLD.severity ||
                ', Malicious=' || OLD.is_malicious::TEXT,
                'Status=' || NEW.status    || ', Severity=' || NEW.severity ||
                ', Malicious=' || NEW.is_malicious::TEXT,
                COALESCE(current_user, 'system')
            );
        END IF;
        -- Always update the timestamp
        NEW.updated_at := CURRENT_TIMESTAMP;

    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO audit_log (table_name, operation, record_id, old_data, performed_by)
        VALUES (
            'indicators',
            'DELETE',
            OLD.indicator_id,
            'Type=' || OLD.indicator_type ||
            ', Value=' || OLD.indicator_value,
            COALESCE(current_user, 'system')
        );
        RETURN OLD;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach trigger to indicators table
CREATE TRIGGER trg_audit_indicators
    BEFORE INSERT OR UPDATE OR DELETE ON indicators
    FOR EACH ROW
    EXECUTE FUNCTION fn_audit_indicators();

-- ============================================================
--  TRIGGER FUNCTION 2: Auto-create incident on Critical IOC
--  Fires on: INSERT on indicators
--  Business Rule: Any Critical+Malicious IOC automatically
--                 opens a security incident
-- ============================================================
CREATE OR REPLACE FUNCTION fn_auto_incident_on_critical()
RETURNS TRIGGER AS $$
DECLARE
    v_incident_id INTEGER;
BEGIN
    IF NEW.severity = 'Critical' AND NEW.is_malicious = TRUE THEN
        INSERT INTO incidents (
            incident_title,
            description,
            severity,
            status,
            affected_systems
        )
        VALUES (
            'AUTO-GENERATED: Critical ' || NEW.indicator_type ||
            ' Detected — ' || NEW.indicator_value,
            'This incident was automatically created when a Critical indicator ' ||
            'was added to the system. Indicator type: ' || NEW.indicator_type ||
            ', Value: ' || NEW.indicator_value ||
            '. Immediate investigation required.',
            'Critical',
            'Open',
            'Unknown — requires investigation'
        )
        RETURNING incident_id INTO v_incident_id;

        -- Link the indicator to the new incident
        INSERT INTO incident_indicators (incident_id, indicator_id)
        VALUES (v_incident_id, NEW.indicator_id);

        RAISE NOTICE 'AUTO-INCIDENT: Created incident #% for critical indicator %',
                      v_incident_id, NEW.indicator_value;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auto_incident_critical
    AFTER INSERT ON indicators
    FOR EACH ROW
    EXECUTE FUNCTION fn_auto_incident_on_critical();

-- ============================================================
--  TRIGGER FUNCTION 3: Prevent deleting Active+Critical indicators
--  Fires on: BEFORE DELETE on indicators
--  Business Rule: Cannot delete an Active Critical indicator;
--                 must archive it first
-- ============================================================
CREATE OR REPLACE FUNCTION fn_prevent_critical_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.severity = 'Critical' AND OLD.status = 'Active' THEN
        RAISE EXCEPTION
            'Cannot delete an Active Critical indicator (ID=%). '
            'Archive it first by setting status = ''Archived''.', OLD.indicator_id;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_prevent_critical_delete
    BEFORE DELETE ON indicators
    FOR EACH ROW
    EXECUTE FUNCTION fn_prevent_critical_delete();

-- ============================================================
--  TRIGGER FUNCTION 4: Auto-update incidents.updated_at
--  Fires on: UPDATE on incidents
-- ============================================================
CREATE OR REPLACE FUNCTION fn_update_incident_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    -- If status changes to Resolved, set resolved_at automatically
    IF NEW.status = 'Resolved' AND OLD.status <> 'Resolved' THEN
        NEW.resolved_at := CURRENT_TIMESTAMP;
        RAISE NOTICE 'Incident #% marked as Resolved at %',
                      NEW.incident_id, NEW.resolved_at;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_incident_timestamp
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION fn_update_incident_timestamp();

-- ============================================================
--  TRIGGER FUNCTION 5: Audit threat_actor changes
-- ============================================================
CREATE OR REPLACE FUNCTION fn_audit_threat_actors()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        NEW.updated_at := CURRENT_TIMESTAMP;
        INSERT INTO audit_log (table_name, operation, record_id, old_data, new_data, performed_by)
        VALUES (
            'threat_actors', 'UPDATE', NEW.actor_id,
            'Name=' || OLD.actor_name || ', Type=' || OLD.actor_type,
            'Name=' || NEW.actor_name || ', Type=' || NEW.actor_type,
            COALESCE(current_user, 'system')
        );
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO audit_log (table_name, operation, record_id, new_data, performed_by)
        VALUES (
            'threat_actors', 'INSERT', NEW.actor_id,
            'Name=' || NEW.actor_name || ', Type=' || NEW.actor_type,
            COALESCE(current_user, 'system')
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_actors
    BEFORE INSERT OR UPDATE ON threat_actors
    FOR EACH ROW
    EXECUTE FUNCTION fn_audit_threat_actors();

-- ============================================================
--  STORED FUNCTION 1: Get indicator risk score
--  Demonstrates: PL/pgSQL function, CASE, calculation
-- ============================================================
CREATE OR REPLACE FUNCTION fn_indicator_risk_score(p_indicator_id INTEGER)
RETURNS DECIMAL(5,2) AS $$
DECLARE
    v_severity       VARCHAR(20);
    v_confidence     INTEGER;
    v_is_malicious   BOOLEAN;
    v_severity_score DECIMAL(5,2);
    v_risk_score     DECIMAL(5,2);
BEGIN
    SELECT severity, confidence_score, is_malicious
    INTO   v_severity, v_confidence, v_is_malicious
    FROM   indicators
    WHERE  indicator_id = p_indicator_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Indicator ID % not found', p_indicator_id;
    END IF;

    -- Map severity to numeric score
    v_severity_score := CASE v_severity
        WHEN 'Critical' THEN 10.0
        WHEN 'High'     THEN  7.5
        WHEN 'Medium'   THEN  5.0
        WHEN 'Low'      THEN  2.5
        ELSE 1.0
    END;

    -- Combine severity + confidence + malicious flag
    v_risk_score := (v_severity_score * 0.6)
                  + (v_confidence / 10.0 * 0.4)
                  + (CASE WHEN v_is_malicious THEN 1.0 ELSE 0.0 END);

    RETURN ROUND(v_risk_score, 2);
END;
$$ LANGUAGE plpgsql;

-- ============================================================
--  STORED FUNCTION 2: Count indicators by severity (subquery demo)
-- ============================================================
CREATE OR REPLACE FUNCTION fn_count_by_severity(p_severity VARCHAR)
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM indicators
    WHERE severity = p_severity
      AND status   = 'Active'
      AND is_malicious = TRUE;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
--  STORED FUNCTION 3: Get actors with more indicators than avg
--  Demonstrates: Subquery with ALL / EXISTS concept
-- ============================================================
CREATE OR REPLACE FUNCTION fn_high_activity_actors()
RETURNS TABLE(actor_name VARCHAR, indicator_count BIGINT) AS $$
BEGIN
    RETURN QUERY
    SELECT ta.actor_name, COUNT(i.indicator_id) AS indicator_count
    FROM threat_actors ta
    JOIN indicators i ON ta.actor_id = i.actor_id
    GROUP BY ta.actor_name
    HAVING COUNT(i.indicator_id) > (
        -- Subquery: average indicators per actor
        SELECT AVG(cnt)
        FROM (
            SELECT COUNT(*) AS cnt
            FROM indicators
            GROUP BY actor_id
        ) sub
    )
    ORDER BY indicator_count DESC;
END;
$$ LANGUAGE plpgsql;

SELECT 'Triggers and functions created successfully!' AS status;
