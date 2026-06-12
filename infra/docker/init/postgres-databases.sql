-- AICC per-service databases. Each backend service owns one logical
-- database; cross-service access goes through HTTP or the event bus,
-- never direct DB peering. This is the Sprint 1 split and matches the
-- `DATABASE_URL` defaults in each service's `.env.example`.
SELECT 'CREATE DATABASE aicc_auth'      WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aicc_auth') \gexec
SELECT 'CREATE DATABASE aicc_security'  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aicc_security') \gexec
SELECT 'CREATE DATABASE aicc_incident'  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aicc_incident') \gexec
SELECT 'CREATE DATABASE aicc_compliance' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aicc_compliance') \gexec
SELECT 'CREATE DATABASE aicc_integration' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'aicc_integration') \gexec
