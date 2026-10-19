-- Example query for cloud audit logs (adapt to your platform)
-- Looks for unusual sequences: document/tool read followed by secret access

SELECT
  timestamp,
  principal_email,
  method_name,
  resource_name
FROM
  `project.dataset.cloudaudit_googleapis_com_activity_*`
WHERE
  timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
  AND (
    method_name LIKE '%secret%'
    OR resource_name LIKE '%ssh%'
    OR resource_name LIKE '%credential%'
  )
  AND principal_email IN (
    -- principals known to run agents or MCP servers
    SELECT DISTINCT principal_email
    FROM `project.dataset.cloudaudit_googleapis_com_activity_*`
    WHERE method_name LIKE '%storage.objects.get%'
      AND timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
  )
ORDER BY timestamp DESC
LIMIT 100;
