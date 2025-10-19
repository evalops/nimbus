-- Migration: Add executor column to jobs table
-- Version: 1.1
-- Date: 2025-10-19
-- Description: Add executor column to support different job execution backends

-- Add executor column with default value
ALTER TABLE jobs ADD COLUMN executor VARCHAR(32) NOT NULL DEFAULT 'firecracker';

-- Update any existing jobs to have the firecracker executor
UPDATE jobs SET executor = 'firecracker' WHERE executor IS NULL;

-- Create index for executor-based queries (optional, for future performance)
CREATE INDEX IF NOT EXISTS ix_jobs_executor ON jobs(executor);
