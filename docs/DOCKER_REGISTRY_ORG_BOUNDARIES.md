# Docker Registry Org Boundaries

## Status: PARTIAL IMPLEMENTATION

This document outlines the multi-tenant isolation requirements for the Nimbus Docker registry.

## Current State

- ✅ `validate_repository_access()` helper function added
- ✅ `org_id` column added to `blobs` table
- ✅ Scope validation integrated via `validate_cache_scope()`
- ⚠️ Only `/v2/{name}/blobs/uploads/` endpoint updated with validation
- ❌ Remaining endpoints need validation

## Required Changes

### 1. Enforce Org Prefix on All Endpoints

All repository names MUST be prefixed with `org-{id}/` to enforce org boundaries.

**Example:**
- ✅ Good: `org-123/myapp/web:latest`
- ❌ Bad: `myapp/web:latest`

### 2. Update All Docker Registry Endpoints

The following endpoints need `validate_repository_access()` calls:

#### Blob Operations
- [x] `POST /v2/{name}/blobs/uploads/` - upload init (DONE)
- [ ] `PATCH /v2/{name}/blobs/uploads/{id}` - upload chunk
- [ ] `PUT /v2/{name}/blobs/uploads/{id}` - finalize upload
- [ ] `HEAD /v2/{name}/blobs/{digest}` - blob stat
- [ ] `GET /v2/{name}/blobs/{digest}` - blob fetch

#### Manifest Operations
- [ ] `PUT /v2/{name}/manifests/{reference}` - push manifest
- [ ] `GET /v2/{name}/manifests/{reference}` - fetch manifest
- [ ] `HEAD /v2/{name}/manifests/{reference}` - manifest stat

### 3. Code Pattern

Apply this pattern to each endpoint:

```python
@app.get("/v2/{name:path}/blobs/{digest}")
async def fetch_blob(
    name: str,
    digest: str,
    token: CacheToken = Depends(require_cache_token),  # Changed from _
    state: DockerCacheState = Depends(get_state),
) -> StreamingResponse:
    repository = sanitize_repository(name)
    validate_repository_access(repository, token, "pull")  # ADD THIS
    # ... rest of implementation
```

### 4. Metadata Schema

The `blobs` table now includes `org_id`:

```sql
CREATE TABLE blobs (
    digest TEXT PRIMARY KEY,
    org_id INTEGER,           -- Added for multi-tenancy
    size INTEGER NOT NULL,
    last_access REAL NOT NULL
)
```

Update `record_blob()` calls to include org_id:

```python
state.metrics.record_blob(digest, size, org_id=token.organization_id)
```

### 5. Scope Requirements

Operations require specific scopes:
- **Push operations** (POST, PUT, PATCH): Require `push:org-{id}` scope
- **Pull operations** (GET, HEAD): Require `pull:org-{id}` scope

The `validate_cache_scope()` function enforces these rules.

### 6. Storage Quotas (Future)

Per-org storage quotas should be enforced:

```python
def total_blob_bytes_by_org(self, org_id: int) -> int:
    with self._connect() as conn:
        cur = conn.execute(
            "SELECT COALESCE(SUM(size), 0) FROM blobs WHERE org_id = ?",
            (org_id,)
        )
        (total,) = cur.fetchone()
    return int(total)
```

Add quota checking before finalizing uploads:

```python
current_usage = state.metrics.total_blob_bytes_by_org(token.organization_id)
max_quota = get_org_quota(token.organization_id)  # from config
if current_usage + session.size > max_quota:
    raise HTTPException(
        status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
        detail=f"Org storage quota exceeded"
    )
```

### 7. Cross-Org Access Tests

Add integration tests to verify isolation:

```python
def test_cross_org_blob_access():
    """Verify org-123 cannot access org-456 blobs"""
    token_123 = mint_cache_token(secret=SECRET, organization_id=123, ttl_seconds=300)
    token_456 = mint_cache_token(secret=SECRET, organization_id=456, ttl_seconds=300)
    
    # Push blob as org-456
    response = client.post(
        "/v2/org-456/myapp/blobs/uploads/",
        headers={"Authorization": f"Bearer {token_456.token}"}
    )
    assert response.status_code == 202
    
    # Try to access as org-123 (should fail)
    response = client.get(
        "/v2/org-456/myapp/blobs/sha256:abc123",
        headers={"Authorization": f"Bearer {token_123.token}"}
    )
    assert response.status_code == 403
```

### 8. Migration Guide

For existing deployments with non-prefixed repositories:

```python
# Add org prefix to existing repositories
import sqlite3

conn = sqlite3.connect("docker-cache/metadata.db")

# Get default org (from first token or config)
DEFAULT_ORG_ID = 1

# Update manifests table
conn.execute("""
    UPDATE manifests 
    SET repository = 'org-' || ? || '/' || repository
    WHERE repository NOT LIKE 'org-%'
""", (DEFAULT_ORG_ID,))

# Update blobs table
conn.execute("""
    UPDATE blobs
    SET org_id = ?
    WHERE org_id IS NULL
""", (DEFAULT_ORG_ID,))

conn.commit()
conn.close()
```

### 9. Client Configuration

Docker clients must use the org-prefixed naming:

```bash
# docker-compose.yml or similar
services:
  builder:
    build:
      context: .
      cache_from:
        - registry.nimbus.internal/org-123/myapp/cache:latest
      cache_to:
        - type=registry,ref=registry.nimbus.internal/org-123/myapp/cache:latest
```

## Testing Checklist

Before production:

- [ ] All endpoints validate org boundaries
- [ ] Cross-org access attempts return 403
- [ ] Blob metadata includes org_id
- [ ] Storage quotas enforced per-org
- [ ] Integration tests pass for multi-tenant scenarios
- [ ] Performance impact measured (minimal expected)

## Rollout Plan

1. **Phase 1** (Current): Add validation to upload endpoints
2. **Phase 2**: Add validation to read endpoints
3. **Phase 3**: Enforce org prefix in client configuration
4. **Phase 4**: Enable per-org storage quotas
5. **Phase 5**: Add monitoring and alerting for quota violations
