INSERT INTO threat_actors
  (actor_name, actor_type, origin_country, motivation,
   sophistication_level, aliases, description, created_by)
VALUES
  ('APT-Lazarus', 'APT', 'North Korea', 'Financial / Espionage',
   9, 'Hidden Cobra, Zinc', 'State-sponsored group targeting financial institutions', 1)
RETURNING actor_id;

SELECT
    actor_id,
    actor_name,
    actor_type,
    origin_country,
    sophistication_level,
    total_indicators,
    incident_count,
    last_activity
FROM   vw_actor_summary
ORDER  BY sophistication_level DESC;

SELECT
    ta.actor_name,
    ta.actor_type,
    ta.origin_country,
    ta.sophistication_level,
    ta.motivation,
    ta.description,
    i.indicator_type,
    i.indicator_value,
    i.severity
FROM   threat_actors ta
LEFT JOIN indicators i ON ta.actor_id = i.actor_id
WHERE  ta.actor_id = 1;
