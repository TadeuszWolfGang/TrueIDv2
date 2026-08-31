-- TOTP replay protection (RFC 6238 §5.2): remember the last TOTP timestep
-- accepted for each user so codes cannot be reused within their validity
-- window. Reset to NULL whenever a new setup secret is stored or TOTP is
-- disabled.
ALTER TABLE users ADD COLUMN totp_last_timestep INTEGER;
