-- maria_net queue. Tenant tables and this schema share ENGINE=TidesDB so the
-- trigger insert commits and rolls back with the user statement.
--
-- Commit durability follows tidesdb_memtable_sync_mode, which defaults to FULL.
-- The 11.4 TideSQL package has no per-table SYNC_MODE option.
-- Daemon sessions must leave tidesdb_single_delete_primary at 0: claim updates
-- columns that are not the primary key.
--
-- Only the daemon account may read net.webhook. A tenant grant that can
-- select the secret can forge X-Maria-Signature. Create the two accounts
-- with `maria-net accounts`. Do not grant net.* to the tenant.
--
-- INSTALL SONAME 'maria_net' is the on/off mark. The HTTP process stays
-- outside mysqld and claims only while that plugin is ACTIVE.

CREATE DATABASE IF NOT EXISTS net;

CREATE TABLE IF NOT EXISTS net.webhook (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  table_schema VARCHAR(64) NOT NULL,
  table_name VARCHAR(64) NOT NULL,
  events VARCHAR(64) NOT NULL,
  method VARCHAR(8) NOT NULL,
  url TEXT NOT NULL,
  headers JSON NULL,
  secret VARBINARY(128) NOT NULL,
  timeout_ms INT UNSIGNED NOT NULL DEFAULT 5000,
  max_attempts TINYINT UNSIGNED NOT NULL DEFAULT 5,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id)
) ENGINE=TidesDB;

-- One secondary index. Completed and dead rows are deleted. The density trigger
-- compacts the tombstones that insert-then-delete leaves behind.
CREATE TABLE IF NOT EXISTS net.http_request_queue (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  webhook_id BIGINT UNSIGNED NOT NULL,
  method VARCHAR(8) NOT NULL,
  url TEXT NOT NULL,
  headers JSON NULL,
  body LONGBLOB NULL,
  timeout_ms INT UNSIGNED NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'pending',
  claim_token CHAR(32) NULL,
  locked_at DATETIME(3) NULL,
  available_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
  max_attempts TINYINT UNSIGNED NOT NULL DEFAULT 5,
  last_error VARCHAR(512) NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id),
  KEY idx_claim (status, available_at, id)
) ENGINE=TidesDB TOMBSTONE_DENSITY_TRIGGER=5000 TOMBSTONE_DENSITY_MIN_ENTRIES=1024;

-- Append-only response log. No secondary index. Rows expire after 7 days.
CREATE TABLE IF NOT EXISTS net.http_response (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  request_id BIGINT UNSIGNED NOT NULL,
  webhook_id BIGINT UNSIGNED NOT NULL,
  attempt TINYINT UNSIGNED NOT NULL,
  outcome VARCHAR(16) NOT NULL,
  status_code INT NULL,
  latency_ms INT UNSIGNED NULL,
  error VARCHAR(512) NULL,
  body MEDIUMBLOB NULL,
  created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (id)
) ENGINE=TidesDB TTL=604800;
