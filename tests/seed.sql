-- ============================================================================
-- SOVEREIGN ENGINE MUNICIPAL DATABASE INITIAL SEED DATA
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- 1. SEED MUNICIPAL DEPARTMENTS
-- ----------------------------------------------------------------------------
INSERT INTO departments (department_id, code, name) VALUES
    ('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'DEPT_ROADS', 'Department of Public Works & Infrastructure'),
    ('b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22', 'DEPT_WATER', 'Department of Water & Waste Management'),
    ('c2eebc99-9c0b-4ef8-bb6d-6bb9bd380a33', 'DEPT_ADMIN', 'Municipal Finance & Procurement Authority')
ON CONFLICT (code) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. SEED INITIAL ENGINE EPOCHS
-- ----------------------------------------------------------------------------
-- Epoch 1001: Active Sealed Epoch (Roads)
-- Epoch 1002: Active Idle Epoch (Water)
INSERT INTO engine_epochs (
    epoch_id,
    department_id,
    typestate,
    genesis_seed,
    initial_lineage_hash,
    terminal_state_hash,
    opened_at,
    sealed_at
) VALUES (
    1001,
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'SEALED',
    '\x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20', -- 32-byte Genesis Seed
    '\xa1b2c3d4e5f6071829304152637485960a1b2c3d4e5f60718293041526374859', -- Genesis Hash
    '\xf9e8d7c6b5a403122130495867768594a1b2c3d4e5f607182930415263748596', -- Terminal Hash Anchor
    CURRENT_TIMESTAMP - INTERVAL '7 days',
    CURRENT_TIMESTAMP - INTERVAL '1 hour'
), (
    1002,
    'b1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22',
    'IDLE',
    '\x99887766554433221100fefd2233445566778899aabbccddeeff001122334455',
    '\xb2c3d4e5f6071829304152637485960a1b2c3d4e5f60718293041526374859a1',
    NULL,
    CURRENT_TIMESTAMP - INTERVAL '2 days',
    NULL
) ON CONFLICT (epoch_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 3. SEED MUNICIPAL AUDIT EVENTS (EPOCH 1001 LINEAGE TRACE)
-- ----------------------------------------------------------------------------
INSERT INTO municipal_events (
    event_id,
    epoch_id,
    sequence_number,
    department_id,
    event_type,
    payload_data,
    canonical_payload_hash,
    running_lineage_hash,
    created_at
) VALUES 
-- Event 1: RFP Publication
(
    '11111111-1111-1111-1111-111111111111',
    1001,
    1,
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'RFP_PUBLISHED',
    '{
        "rfp_id": "RFP-2026-88B",
        "title": "Main Street Resurfacing Phase II",
        "budget_limit_usd": 450000.00,
        "authorizer_id": "USR_OFFICIAL_402"
    }'::jsonb,
    '\x81216d63bb126f544682c97a8e7ef9787e97d19760d621535492d54e4c2f1021',
    '\x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    CURRENT_TIMESTAMP - INTERVAL '6 days'
),
-- Event 2: Vendor Bid Submission
(
    '22222222-2222-2222-2222-222222222222',
    1001,
    2,
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'BID_SUBMITTED',
    '{
        "rfp_id": "RFP-2026-88B",
        "vendor_tax_id": "XX-XXX8492",
        "vendor_name": "Apex Paving Systems LLC",
        "bid_amount_usd": 412500.00,
        "submitted_timestamp": "2026-08-30T14:22:00Z"
    }'::jsonb,
    '\x223344556677889900aabbccddeeff00112233445566778899aabbccddeeff00',
    '\x3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d',
    CURRENT_TIMESTAMP - INTERVAL '4 days'
),
-- Event 3: Invoice Payout Approval
(
    '33333333-3333-3333-3333-333333333333',
    1001,
    3,
    'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11',
    'PAYOUT_APPROVED',
    '{
        "rfp_id": "RFP-2026-88B",
        "invoice_id": "INV-90412",
        "vendor_tax_id": "XX-XXX8492",
        "payout_amount_usd": 100000.00,
        "milestone": "30% Asphalt Clearing Completed",
        "approved_by": "TREASURER_MUNICIPAL_01"
    }'::jsonb,
    '\x445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233',
    '\xf9e8d7c6b5a403122130495867768594a1b2c3d4e5f607182930415263748596', -- Terminal Hash Match
    CURRENT_TIMESTAMP - INTERVAL '1 hour'
);

-- ----------------------------------------------------------------------------
-- 4. SEED COMMITMENT RECEIPT FOR SEALED EPOCH (EPOCH 1001)
-- ----------------------------------------------------------------------------
INSERT INTO commitment_receipts (
    receipt_id,
    epoch_id,
    terminal_hash,
    receipt_commitment,
    canonical_frame_bytes,
    is_rearm_verified,
    verified_at
) VALUES (
    '44444444-4444-4444-4444-444444444444',
    1001,
    '\xf9e8d7c6b5a403122130495867768594a1b2c3d4e5f607182930415263748596', -- Matches Terminal Hash
    '\xd4c3b2a10f9e8d7c6b5a403122130495867768594a1b2c3d4e5f607182930415', -- C_receipt
    '\x00000000000003e9000000033333333333333333333333333333333333333333333333333333333333333333', -- Frame payload
    FALSE,
    NULL
) ON CONFLICT (epoch_id) DO NOTHING;

COMMIT;
