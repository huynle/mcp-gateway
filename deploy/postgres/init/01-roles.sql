-- Local development only (Compose). Runs once when the postgres volume is
-- first initialised, as the superuser "gateway" in database "gateway".
--
-- Migration 00001 creates these roles NOLOGIN when they do not exist and only
-- adjusts their RLS attributes when they do, so creating them here with a
-- LOGIN password gives the Compose gateway something to connect as without a
-- password ever appearing in a migration. In production create the roles the
-- same way (LOGIN + password from your secret store) before the first
-- `migrate up`, or run the migration first and then ALTER ROLE ... LOGIN.
CREATE ROLE gateway_app  LOGIN PASSWORD 'gateway-app-dev'  NOBYPASSRLS;
CREATE ROLE gateway_jobs LOGIN PASSWORD 'gateway-jobs-dev' BYPASSRLS;
