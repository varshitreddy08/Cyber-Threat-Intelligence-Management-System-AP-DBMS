SELECT user_id, username, email, role, department
FROM   ctims_users
WHERE  username      = 'admin'
  AND  password_hash = 'admin123'
  AND  is_active     = TRUE;

UPDATE ctims_users
SET    last_login = CURRENT_TIMESTAMP
WHERE  user_id = 1;

SELECT user_id, username, role, email, department, is_active, created_at
FROM   ctims_users
ORDER  BY user_id;
