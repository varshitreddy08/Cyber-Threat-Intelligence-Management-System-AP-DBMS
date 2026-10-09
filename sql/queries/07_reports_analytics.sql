SELECT * FROM vw_dashboard;

SELECT * FROM vw_severity_stats;

SELECT
    indicator_type,
    indicator_value,
    confidence_score,
    rank_in_type,
    overall_rank,
    pct_of_max
FROM   vw_indicator_ranking
ORDER  BY overall_rank
LIMIT  20;

SELECT
    i.indicator_type,
    i.indicator_value,
    i.severity,
    ta.actor_name
FROM   indicators i
INNER JOIN threat_actors ta ON i.actor_id = ta.actor_id;

SELECT
    i.indicator_type,
    i.indicator_value,
    i.severity,
    COALESCE(ta.actor_name, 'Unknown') AS actor
FROM   indicators i
LEFT JOIN threat_actors ta ON i.actor_id = ta.actor_id;

SELECT
    ta.actor_name,
    ta.actor_type,
    COALESCE(i.indicator_value, '(none)') AS indicator
FROM   indicators i
RIGHT JOIN threat_actors ta ON i.actor_id = ta.actor_id
ORDER  BY ta.actor_name;

SELECT indicator_type, indicator_value, confidence_score
FROM   indicators
WHERE  confidence_score > (SELECT AVG(confidence_score) FROM indicators)
ORDER  BY confidence_score DESC;

SELECT actor_name, actor_type
FROM   threat_actors ta
WHERE  EXISTS (
    SELECT 1
    FROM   indicators i
    WHERE  i.actor_id = ta.actor_id
);

SELECT * FROM fn_high_activity_actors();

SELECT * FROM fn_count_by_severity();

WITH actor_counts AS (
    SELECT
        ta.actor_name,
        COUNT(i.indicator_id)                                          AS total_iocs,
        COUNT(i.indicator_id) FILTER (WHERE i.severity = 'Critical')  AS critical_iocs
    FROM   threat_actors ta
    LEFT JOIN indicators i ON ta.actor_id = i.actor_id
    GROUP  BY ta.actor_name
)
SELECT *
FROM   actor_counts
ORDER  BY total_iocs DESC
LIMIT  3;
