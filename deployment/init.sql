-- AI-NIDS PostgreSQL Initialization Script
-- Creates necessary extensions and initial setup

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create indexes for better query performance (will be applied after tables are created)
-- These are hints for manual optimization after Flask-Migrate creates the schema

-- Function to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE ai_nids TO nids;

-- Create schema for better organization (optional)
-- CREATE SCHEMA IF NOT EXISTS nids;
-- ALTER ROLE nids SET search_path TO nids, public;

-- Mitigation action audit table (for autonomous response logging)
CREATE TABLE IF NOT EXISTS mitigation_action_logs (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(128) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    action_taken VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL,
    rollback_available BOOLEAN DEFAULT FALSE,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_mitigation_action_logs_attack_id ON mitigation_action_logs (attack_id);
CREATE INDEX IF NOT EXISTS idx_mitigation_action_logs_timestamp ON mitigation_action_logs (timestamp);
