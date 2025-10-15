# Database Migrations

## Current State

Nimbus currently uses `ensure_schema()` which creates tables if they don't exist. This works for development but is not suitable for production.

## Migration Strategy

For production deployments:

1. **Initial deployment**: Run `ensure_schema()` once to create the baseline schema
2. **Schema changes**: Apply migrations manually or via deployment scripts
3. **Future**: Adopt full Alembic migrations when needed for complex schema changes

## Manual Migration Process

### Adding a New Column

```sql
-- Example: Add a new column to jobs table
ALTER TABLE jobs ADD COLUMN new_field VARCHAR(255);
```

### Creating Indexes

```sql
-- Indexes for performance
CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS ix_jobs_updated_at ON jobs(updated_at);
CREATE INDEX IF NOT EXISTS ix_jobs_agent_id ON jobs(agent_id);
CREATE INDEX IF NOT EXISTS ix_job_leases_expires ON job_leases(lease_expires_at);
CREATE INDEX IF NOT EXISTS ix_ssh_agent_status_expires ON ssh_sessions(agent_id, status, expires_at);
```

### Adding Constraints

```sql
-- Add unique constraint for SSH sessions
ALTER TABLE ssh_sessions ADD CONSTRAINT uq_ssh_agent_port UNIQUE (agent_id, host_port);
```

## Current Schema Version

**Version**: 1.0 (2025-10-15)

**Tables:**
- `jobs` - Job records and status
- `job_leases` - Lease fencing with fence tokens
- `agent_credentials` - Agent token versions
- `agent_token_audit` - Token rotation audit trail
- `ssh_sessions` - SSH session management

**Key Features:**
- Multi-tenant isolation support (org_id/repo_id)
- Lease fencing with version-based CAS
- SSH port allocation with uniqueness constraints
- Comprehensive indexes for query performance

## Production Deployment

Before first deployment:

```bash
# Set database URL
export NIMBUS_DATABASE_URL="sqlite+aiosqlite:///./nimbus.db"

# Run application - it will create schema via ensure_schema()
uvicorn nimbus.control_plane.main:app
```

For schema changes:

1. Test migration SQL in staging
2. Apply during maintenance window
3. Restart services
4. Verify functionality

## Future: Full Alembic Integration

When needed (complex migrations, rollbacks):

1. Generate baseline migration from current schema
2. Configure Alembic for async SQLAlchemy
3. Create version-controlled migration files
4. Deploy with `alembic upgrade head`

For now, the current approach is adequate for pilot deployments.
