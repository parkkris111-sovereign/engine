# Performance Optimization Patches

This document describes the performance optimizations applied to the Sovereign Engine Municipal Worker.

## Changes Summary

### 1. Combined Database Queries (Fixes N+1 Problem)

**Issue**: Two separate queries were executed in the same transaction:
- Query 1: Fetch epoch record with `FOR UPDATE` lock
- Query 2: Fetch last event for lineage state

**Solution**: Merged into a single query using `LEFT JOIN`
```sql
SELECT e.*, m.sequence_number, m.running_lineage_hash
FROM engine_epochs e
LEFT JOIN (...) m ON e.epoch_id = m.epoch_id
WHERE e.epoch_id = $1
FOR UPDATE OF e
```

**Benefits**:
- Eliminates one database round-trip per request
- Reduces transaction time
- Maintains ACID guarantees with `FOR UPDATE`

**Expected Improvement**: ~20-30ms latency reduction per request (depends on network latency)

### 2. Database Indexes for Query Performance

**New Indexes Created**:

1. `idx_municipal_events_epoch_sequence(epoch_id, sequence_number DESC)`
   - Critical path: Enables efficient last-event lookups
   - Without this index: Full table scan O(n)
   - With this index: Seek + limit O(log n)

2. `idx_engine_epochs_epoch_id(epoch_id)`
   - Supports epoch state lookups

3. `idx_municipal_events_department(epoch_id, department_id, created_at DESC)`
   - Enables departmental audit queries

4. `idx_municipal_events_type(event_type, created_at DESC)`
   - Supports event type analytics

**Application**:
Run migrations before deploying:
```bash
sqlx migrate run --database-url $DATABASE_URL
```

### 3. Connection Pool Configuration

**Old**:
```rust
.max_connections(10)  // Hard-coded, too small
```

**New**:
```rust
let max_connections: u32 = std::env::var("DB_MAX_CONNECTIONS")
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(50);

.max_connections(max_connections)
```

**Benefits**:
- Environment-driven configuration
- Default 50 connections (suitable for high-concurrency scenarios)
- Prevents connection pool starvation

**Deployment**:
Set environment variable:
```bash
export DB_MAX_CONNECTIONS=50  # or adjust based on expected load
```

### 4. Remove Hex Encoding from Hot Path

**Issue**: Converting 32-byte hashes to hex strings on every request adds CPU overhead

**Before**:
```rust
canonical_payload_hash: hex::encode(payload_hash_bytes),
running_lineage_hash: hex::encode(new_lineage_hash.as_bytes()),
```

**After**:
```rust
#[derive(Serialize)]
pub struct IngestEventResponse {
    #[serde(with = "hex_serialize")]
    pub canonical_payload_hash: [u8; 32],
    #[serde(with = "hex_serialize")]
    pub running_lineage_hash: [u8; 32],
}
```

Custom serializer handles hex encoding during JSON serialization only, with better memory locality.

**Benefits**:
- Encoding happens once, in serializer (lazily)
- Stored as raw bytes internally
- More efficient memory layout

### 5. Eliminate Byte Array Allocations

**Before**:
```rust
let mut hash = [0u8; 32];
hash.copy_from_slice(&row.running_lineage_hash);  // Copy + allocation
```

**After**:
```rust
let hash_bytes: [u8; 32] = combined
    .running_lineage_hash
    .as_deref()
    .ok_or_else(...)?  
    .try_into()        // Direct conversion, minimal allocations
    .map_err(...)?;
```

**Benefits**:
- Fewer allocations on stack
- Compiler can optimize better
- Reduced memory pressure

### 6. Environment-Based Tracing

**Before**:
```rust
tracing_subscriber::fmt::init();  // All levels enabled
tracing::info!("...");            // Every request logged
```

**After**:
```rust
tracing_subscriber::fmt()
    .with_env_filter(
        tracing_subscriber::EnvFilter::from_default_env()
    )
    .init();
```

**Benefits**:
- Default to `info` level (less verbose)
- Set `RUST_LOG=debug` or `trace` only when needed
- Reduces per-request overhead
- Better performance in production

### 7. Optimized Cargo Dependencies

**Removed**: `tokio = { features = ["full"] }`

**Added**: Only needed features:
```toml
tokio = { version = "1", features = [
    "rt-multi-thread",      # Multi-threaded runtime
    "macros",               # #[tokio::main], #[tokio::test]
    "sync",                 # Synchronization primitives
    "time",                 # Timer utilities
    "signal-hook-tokio"     # Signal handling
] }
```

**Benefits**:
- Smaller binary size
- Faster compilation
- Reduced dependency surface

## Performance Benchmarks

Expected improvements (per request):

| Optimization | Expected Improvement |
|--------------|----------------------|
| Combined queries | ~20-30ms |
| Database indexes | ~50-100ms (for large datasets) |
| Connection pool increase | Variable (reduces blocking) |
| Reduced hex encoding | ~1-2ms |
| Tracing overhead reduction | ~2-5ms |
| **Total** | **~75-140ms** |

*Benchmarks are approximate and depend on:
- Database size (number of events per epoch)
- Network latency to PostgreSQL
- CPU performance
- Payload size

## Deployment Checklist

- [ ] Apply database migrations: `sqlx migrate run --database-url $DATABASE_URL`
- [ ] Update Cargo.toml dependencies
- [ ] Set environment variables:
  - `DB_MAX_CONNECTIONS=50` (or appropriate for your deployment)
  - `RUST_LOG=info` (production) or `debug` (development)
- [ ] Rebuild and deploy: `cargo build --release`
- [ ] Monitor database query performance (check indexes are used)
- [ ] Monitor connection pool utilization

## Monitoring

Recommended metrics to track:

1. **Database Connection Pool**:
   - Current connections in use
   - Max connections configured
   - Connection wait time

2. **Query Performance**:
   - Query duration (especially the combined epoch/event query)
   - Index usage (verify `idx_municipal_events_epoch_sequence` is used)
   - Slow query log

3. **Application Performance**:
   - Request latency (p50, p95, p99)
   - Throughput (events/sec)
   - Memory usage

## Future Optimizations

Potential improvements for future consideration:

1. **Result Caching**: Cache lineage hashes in Redis (immutable data)
2. **Batch Ingestion**: Support bulk event inserts
3. **Query Result Streaming**: For large lineage queries
4. **Connection Pooling Enhancement**: Per-department routing
5. **Cryptographic Optimization**: Profile `ExecutionLineage::extend()`
