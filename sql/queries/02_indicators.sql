INSERT INTO indicators
  (indicator_type, indicator_value, severity, status,
   is_malicious, confidence_score, ip_version, geolocation,
   reputation_score, context, actor_id, reported_by)
VALUES
  ('IP', '192.168.1.105', 'Critical', 'Active',
   TRUE, 90, 'IPv4', 'Mumbai, India',
   10, 'C2 beacon traffic detected', 1, 1)
RETURNING indicator_id;

INSERT INTO indicators
  (indicator_type, indicator_value, severity, status,
   is_malicious, confidence_score, registrar, is_dga, context, actor_id, reported_by)
VALUES
  ('Domain', 'malware-c2.ru', 'High', 'Active',
   TRUE, 85, 'NameCheap', FALSE, 'Phishing campaign domain', 1, 1)
RETURNING indicator_id;

INSERT INTO indicators
  (indicator_type, indicator_value, severity, status,
   is_malicious, confidence_score, has_redirect, context, actor_id, reported_by)
VALUES
  ('URL', 'http://evil.tk/payload.exe', 'High', 'Active',
   TRUE, 80, TRUE, 'Malware dropper URL', 1, 1)
RETURNING indicator_id;

INSERT INTO indicators
  (indicator_type, indicator_value, severity, status,
   is_malicious, confidence_score, hash_type, file_name, file_size_bytes, context, actor_id, reported_by)
VALUES
  ('Hash', 'd41d8cd98f00b204e9800998ecf8427e', 'Medium', 'Active',
   TRUE, 75, 'MD5', 'payload.exe', 204800, 'Malware sample hash', NULL, 1)
RETURNING indicator_id;

SELECT
    i.indicator_id,
    i.indicator_type,
    i.indicator_value,
    i.severity,
    i.status,
    i.confidence_score,
    i.is_malicious,
    COALESCE(ta.actor_name, 'Unknown') AS actor,
    CASE
        WHEN i.confidence_score >= 90 THEN 'Confirmed'
        WHEN i.confidence_score >= 70 THEN 'Probable'
        WHEN i.confidence_score >= 50 THEN 'Suspected'
        ELSE 'Unknown'
    END AS confidence_label
FROM  indicators i
LEFT JOIN threat_actors ta ON i.actor_id = ta.actor_id
ORDER BY
    CASE i.severity
        WHEN 'Critical' THEN 1
        WHEN 'High'     THEN 2
        WHEN 'Medium'   THEN 3
        ELSE 4
    END;

SELECT indicator_id, indicator_type, indicator_value, severity, status
FROM   indicators
WHERE  indicator_value LIKE '%malware%'
ORDER  BY severity;

SELECT indicator_id, indicator_type, indicator_value, severity, confidence_score
FROM   indicators
WHERE  severity    = 'Critical'
  AND  is_malicious = TRUE
ORDER  BY confidence_score DESC;

SELECT
    i.indicator_type,
    i.indicator_value,
    i.severity,
    ta.actor_name
FROM   indicators i
INNER JOIN threat_actors ta ON i.actor_id = ta.actor_id
WHERE  ta.actor_name LIKE '%APT%';

UPDATE indicators
SET    status = 'Archived'
WHERE  indicator_id = 1;

DELETE FROM indicators
WHERE  indicator_id = 5;

SELECT fn_indicator_risk_score(1) AS risk_score;
