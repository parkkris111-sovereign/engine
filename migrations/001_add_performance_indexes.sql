-- Migration: Add performance indexes for municipal audit engine
-- Improves query performance for epoch-based lookups and event ordering

-- Index for efficient last-event lookup per epoch
-- This is the critical path for every event ingestion
CREATE INDEX IF NOT EXISTS idx_municipal_events_epoch_sequence
  ON municipal_events(epoch_id, sequence_number DESC)
  WHERE deleted_at IS NULL;

-- Index for epoch state lookups (used in FOR UPDATE lock)
CREATE INDEX IF NOT EXISTS idx_engine_epochs_epoch_id
  ON engine_epochs(epoch_id)
  WHERE archived = false;

-- Index for department-level audit queries
CREATE INDEX IF NOT EXISTS idx_municipal_events_department
  ON municipal_events(epoch_id, department_id, created_at DESC)
  WHERE deleted_at IS NULL;

-- Index for event type analytics
CREATE INDEX IF NOT EXISTS idx_municipal_events_type
  ON municipal_events(event_type, created_at DESC)
  WHERE deleted_at IS NULL;
