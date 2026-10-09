SELECT
    log_id,
    table_name,
    operation,
    record_id,
    old_data,
    new_data,
    performed_at
FROM   audit_log
ORDER  BY performed_at DESC
LIMIT  30;

SELECT log_id, operation, old_data, new_data, performed_at
FROM   audit_log
WHERE  table_name = 'indicators'
  AND  record_id  = 1
ORDER  BY performed_at DESC;

SELECT operation, COUNT(*) AS total
FROM   audit_log
GROUP  BY operation
ORDER  BY total DESC;
