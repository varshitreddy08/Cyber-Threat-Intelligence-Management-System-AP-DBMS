INSERT INTO vulnerabilities
  (cve_id, title, description, cvss_score,
   affected_product, affected_versions,
   is_patched, patch_available, exploit_available)
VALUES
  ('CVE-2024-1234', 'Remote Code Execution in Apache',
   'Unauthenticated RCE via crafted HTTP request', 9.8,
   'Apache HTTP Server', '2.4.0 - 2.4.51',
   FALSE, TRUE, TRUE)
RETURNING vuln_id;

SELECT
    vuln_id,
    cve_id,
    title,
    cvss_score,
    severity,
    is_patched,
    exploit_available
FROM   vulnerabilities
ORDER  BY cvss_score DESC;

SELECT cve_id, title, cvss_score, severity
FROM   vulnerabilities
WHERE  is_patched  = FALSE
  AND  cvss_score  > (SELECT AVG(cvss_score) FROM vulnerabilities)
ORDER  BY cvss_score DESC;

SELECT cve_id, title, cvss_score
FROM   vulnerabilities v
WHERE  EXISTS (
    SELECT 1
    FROM   vulnerabilities x
    WHERE  x.vuln_id          = v.vuln_id
      AND  x.exploit_available = TRUE
);
