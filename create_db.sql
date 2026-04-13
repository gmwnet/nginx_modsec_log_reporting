/* ============================================================
   Database: security_logs
   Purpose:  NGINX error log + ModSecurity (OWASP CRS) ingestion
   ============================================================ */

-- ----------------------------------------------------------------
-- Create database
-- ----------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS security_logs
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE security_logs;

-- ----------------------------------------------------------------
-- Core ModSecurity / NGINX events table
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS modsecurity_events (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,

    /* === NGINX metadata === */
    event_time DATETIME NOT NULL,
    nginx_level ENUM('debug','info','notice','warn','error','crit','alert','emerg'),
    nginx_pid INT UNSIGNED,
    nginx_tid INT UNSIGNED,
    connection_id INT UNSIGNED,

    client_ip VARCHAR(45) NOT NULL,
    server_name VARCHAR(255),
    host VARCHAR(255),
    request_line TEXT,

    /* === ModSecurity action === */
    http_code SMALLINT UNSIGNED,
    phase TINYINT UNSIGNED,

    /* === Rule identification === */
    rule_id VARCHAR(20),
    rule_file VARCHAR(512),
    rule_line INT,
    rule_rev VARCHAR(20),
    rule_ver VARCHAR(50),

    /* === Messages & scoring === */
    message TEXT,
    matched TEXT,
    data TEXT,

    severity TINYINT,
    maturity TINYINT,
    accuracy TINYINT,

    /* === Correlation === */
    unique_id VARCHAR(40),

    /* === Audit === */
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    /* === Indexes === */
    INDEX idx_event_time (event_time),
    INDEX idx_client_ip (client_ip),
    INDEX idx_rule_id (rule_id),
    INDEX idx_http_code (http_code),
    INDEX idx_unique_id (unique_id),
    INDEX idx_connection_id (connection_id),
    INDEX idx_server_name (server_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- ModSecurity tags (normalized)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS modsecurity_tags (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    tag VARCHAR(100) NOT NULL UNIQUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- Event ↔ Tag mapping table
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS modsecurity_event_tags (
    event_id BIGINT UNSIGNED NOT NULL,
    tag_id INT UNSIGNED NOT NULL,

    PRIMARY KEY (event_id, tag_id),

    CONSTRAINT fk_modsec_evt
        FOREIGN KEY (event_id)
        REFERENCES modsecurity_events(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_modsec_tag
        FOREIGN KEY (tag_id)
        REFERENCES modsecurity_tags(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- OPTIONAL: Raw nginx error log archival (for forensics)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS raw_nginx_error_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    log_time DATETIME NULL,
    raw_line MEDIUMTEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_log_time (log_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ----------------------------------------------------------------
-- FileOffsets
-- ----------------------------------------------------------------

CREATE TABLE IF NOT EXISTS log_file_offsets (
    file_path VARCHAR(512) PRIMARY KEY,
    inode BIGINT UNSIGNED,
    last_position BIGINT UNSIGNED NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- ----------------------------------------------------------------
-- OPTIONAL: Optimize for very large installations
-- Uncomment if needed
-- ----------------------------------------------------------------
/*
ALTER TABLE modsecurity_events
    ADD COLUMN client_ip_bin VARBINARY(16),
    ADD INDEX idx_client_ip_bin (client_ip_bin);
*/

-- ----------------------------------------------------------------
-- Schema complete
-- ----------------------------------------------------------------
``