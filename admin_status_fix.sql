-- Safe compatibility column for the Admin Panel.
ALTER TABLE users
ADD COLUMN IF NOT EXISTS account_status VARCHAR(30);

UPDATE users
SET account_status = COALESCE(status, 'active')
WHERE account_status IS NULL;
