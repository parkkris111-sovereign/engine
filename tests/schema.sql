-- ============================================================================
-- SOVEREIGN ENGINE MUNICIPAL AUDIT DATABASE SCHEMA
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ----------------------------------------------------------------------------
-- 1. MUNICIPAL DEPARTMENTS & AUTHORITIES
-- ----------------------------------------------------------------------------
CREATE TABLE departments (
    department_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(32) UNIQUE NOT NULL, -- e.g., 'DEPT_ROADS', 'DEPT_WATER'
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 2. SOVEREIGN ENGINE EPOCHS
-- Tracks the typestate lifecycle of execution epochs in the engine.
-- ----------------------------------------------------------------------------
CREATE TYPE engine_typestate AS ENUM (
    'UNINITIALIZED',
    'IDLE',
    'SEALED',
    'REARMED'
);

CREATE TABLE engine_epochs (
    epoch_id BIGINT PRIMARY KEY, -- Strictly monotonic u64 epoch counter
    department_id UUID NOT NULL REFERENCES departments(department_id),
    typestate engine_typestate NOT NULL DEFAULT 'IDLE',
    genesis_seed BYTEA NOT NULL CHECK (octet_length(genesis_seed) = 32),
    initial_lineage_hash BYTEA CHECK (octet_length(initial_lineage_hash) = 32),
    terminal_state_hash BYTEA CHECK (octet_length(terminal_state_hash) = 32),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sealed_at TIMESTAMPTZ,
    rearmed_at TIMESTAMPTZ
);

-- ----------------------------------------------------------------------------
-- 3. MUNICIPAL AUDIT EVENTS & LINEAGE TRACE
-- Partitioned by epoch_id for write performance and archival management.
-- ----------------------------------------------------------------------------
CREATE TABLE municipal_events (
    event_id UUID DEFAULT uuid_generate_v4(),
    epoch_id BIGINT NOT NULL,
    sequence_number BIGINT NOT NULL, -- Monotonic index within epoch
    department_id UUID NOT NULL REFERENCES departments(department_id),
    event_type VARCHAR(64) NOT NULL, -- e.g., 'PAYOUT_APPROVAL', 'BID_SUBMISSION'
    
    -- Canonical event payload fed into lineage.extend(payload)
    payload_data JSONB NOT NULL,
    canonical_payload_hash BYTEA NOT NULL CHECK (octet_length(canonical_payload_hash) = 32),
    
    -- Resulting cumulative execution lineage hash after extending
    running_lineage_hash BYTEA NOT NULL CHECK (octet_length(running_lineage_hash) = 32),
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (epoch_id, event_id),
    CONSTRAINT fk_epoch FOREIGN KEY (epoch_id) REFERENCES engine_epochs(epoch_id)
) PARTITION BY RANGE (epoch_id);

-- Default partition for current/initial operations
CREATE TABLE municipal_events_default PARTITION OF municipal_events DEFAULT;

CREATE UNIQUE INDEX idx_events_sequence 
    ON municipal_events (epoch_id, sequence_number);

-- ----------------------------------------------------------------------------
-- 4. COMMITMENT RECEIPTS & PERSISTENCE ANCHORS
-- Stores terminal anchors and commitment proofs verified by verifier.rs.
-- ----------------------------------------------------------------------------
CREATE TABLE commitment_receipts (
    receipt_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    epoch_id BIGINT UNIQUE NOT NULL REFERENCES engine_epochs(epoch_id),
    
    -- H_terminal generated during seal()
    terminal_hash BYTEA NOT NULL CHECK (octet_length(terminal_hash) = 32),
    
    -- C_receipt = compute_expected_commitment(H_terminal, canonical_frame)
    receipt_commitment BYTEA NOT NULL CHECK (octet_length(receipt_commitment) = 32),
    
    -- Raw canonical frame bytes required to verify rearm
    canonical_frame_bytes BYTEA NOT NULL,
    
    is_rearm_verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------------------
-- 5. IMMUTABILITY ENFORCEMENT (DATABASE GUARDS)
-- Prevents updating or deleting existing municipal audit records.
-- ----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION guard_audit_immutability()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'CRITICAL SECURITY VIOLATION: Audit logs and commitment receipts are immutable. Operation % blocked on table %.',
        TG_OP, TG_TABLE_NAME;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Apply immutability trigger to municipal_events
CREATE TRIGGER trg_immutable_events
    BEFORE UPDATE OR DELETE ON municipal_events
    FOR EACH ROW EXECUTE FUNCTION guard_audit_immutability();

-- Apply immutability trigger to commitment_receipts
CREATE TRIGGER trg_immutable_receipts
    BEFORE UPDATE OR DELETE ON commitment_receipts
    FOR EACH ROW EXECUTE FUNCTION guard_audit_immutability();

-- ----------------------------------------------------------------------------
-- 6. INDEXES FOR PERFORMANCE & AUDITOR QUERYING
-- ----------------------------------------------------------------------------
CREATE INDEX idx_events_type_created 
    ON municipal_events (event_type, created_at DESC);

CREATE INDEX idx_events_lineage 
    ON municipal_events (running_lineage_hash);

CREATE INDEX idx_receipts_verification 
    ON commitment_receipts (epoch_id, is_rearm_verified);
