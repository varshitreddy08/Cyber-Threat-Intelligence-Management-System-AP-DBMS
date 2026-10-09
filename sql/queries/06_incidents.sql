INSERT INTO incidents
  (incident_title, description, severity, status,
   affected_systems, impact_description,
   actor_id, assigned_to, reported_by)
VALUES
  ('Ransomware Attack on Finance Server',
   'WannaCry variant detected encrypting files on FINANCE-SRV-01',
   'Critical', 'Open',
   'FINANCE-SRV-01, BACKUP-SRV-02',
   'Complete data encryption, operations halted',
   1, 2, 1)
RETURNING incident_id;

SELECT
    incident_id,
    incident_title,
    severity,
    status,
    threat_actor,
    assigned_analyst,
    open_days,
    sla_status
FROM   vw_open_incidents;

UPDATE incidents
SET    status           = 'Resolved',
       resolution_notes = 'Malware quarantined, systems restored from clean backup'
WHERE  incident_id = 1;

INSERT INTO incident_indicators (incident_id, indicator_id)
VALUES (1, 3);

SELECT
    inc.incident_title,
    i.indicator_type,
    i.indicator_value,
    i.severity
FROM   incidents inc
INNER JOIN incident_indicators ii  ON inc.incident_id  = ii.incident_id
INNER JOIN indicators i            ON ii.indicator_id  = i.indicator_id
WHERE  inc.incident_id = 1;
