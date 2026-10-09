-- ============================================================
--  CYBER THREAT INTELLIGENCE MANAGEMENT SYSTEM (CTIMS)
--  Schema: Tables, Keys, Constraints
--  Covers: DDL (CREATE), Primary Key, Foreign Key, NOT NULL,
--          UNIQUE, CHECK, DEFAULT constraints
-- ============================================================

-- Drop in reverse order (foreign key dependencies)
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS incident_indicators CASCADE;
DROP TABLE IF EXISTS malware_hashes CASCADE;
DROP TABLE IF EXISTS reports CASCADE;
DROP TABLE IF EXISTS incidents CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS malware CASCADE;
DROP TABLE IF EXISTS indicators CASCADE;
DROP TABLE IF EXISTS threat_actors CASCADE;
DROP TABLE IF EXISTS ctims_users CASCADE;

-- ============================================================
--  TABLE 1: ctims_users  (Encapsulation of user identity)
--  Role: Both Admin and Analyst inherit from this concept
-- ============================================================
CREATE TABLE ctims_users (
    user_id      SERIAL PRIMARY KEY,                       -- Auto-increment PK
    username     VARCHAR(50)  NOT NULL UNIQUE,              -- UNIQUE constraint
    password_hash VARCHAR(255) NOT NULL,                    -- NOT NULL
    email        VARCHAR(100) NOT NULL UNIQUE,
    role         VARCHAR(20)  NOT NULL DEFAULT 'analyst'    -- DEFAULT constraint
                 CHECK (role IN ('admin', 'analyst', 'viewer')),  -- CHECK constraint
    department   VARCHAR(100),
    is_active    BOOLEAN DEFAULT TRUE,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login   TIMESTAMP
);

-- ============================================================
--  TABLE 2: threat_actors  (APT groups, cybercriminals, etc.)
-- ============================================================
CREATE TABLE threat_actors (
    actor_id             SERIAL PRIMARY KEY,
    actor_name           VARCHAR(100) NOT NULL,
    actor_type           VARCHAR(30)  NOT NULL
                         CHECK (actor_type IN ('APT','Cybercriminal','Hacktivist',
                                               'Insider','Script Kiddie','Nation-State')),
    origin_country       VARCHAR(60),
    motivation           VARCHAR(200),
    sophistication_level INTEGER      CHECK (sophistication_level BETWEEN 1 AND 10),
    aliases              TEXT,
    first_seen           DATE,
    last_seen            DATE,
    description          TEXT,
    created_by           INTEGER REFERENCES ctims_users(user_id) ON DELETE SET NULL,
    created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
--  TABLE 3: indicators  (IOC - Indicators of Compromise)
--  Demonstrates: Inheritance — IP / Domain / URL / Hash
--  All subtypes stored in one table (Table-Per-Hierarchy)
-- ============================================================
CREATE TABLE indicators (
    indicator_id      SERIAL PRIMARY KEY,
    indicator_type    VARCHAR(20) NOT NULL
                      CHECK (indicator_type IN ('IP','Domain','URL','Hash')),
    indicator_value   VARCHAR(500) NOT NULL,
    severity          VARCHAR(20)  NOT NULL DEFAULT 'Medium'
                      CHECK (severity IN ('Critical','High','Medium','Low')),
    status            VARCHAR(20)  NOT NULL DEFAULT 'Active'
                      CHECK (status IN ('Active','Inactive','Archived')),
    is_malicious      BOOLEAN DEFAULT TRUE,
    confidence_score  INTEGER      CHECK (confidence_score BETWEEN 0 AND 100),

    -- IP-specific columns (NULL for other types)
    ip_version        VARCHAR(4)   CHECK (ip_version IN ('IPv4','IPv6')),
    geolocation       VARCHAR(200),
    reputation_score  INTEGER      CHECK (reputation_score BETWEEN 0 AND 100),

    -- Domain-specific columns
    registrar         VARCHAR(100),
    is_dga            BOOLEAN,         -- Domain Generation Algorithm flag

    -- URL-specific columns
    has_redirect      BOOLEAN,

    -- Hash-specific columns
    hash_type         VARCHAR(10)  CHECK (hash_type IN ('MD5','SHA1','SHA256','SHA512')),
    file_name         VARCHAR(255),
    file_size_bytes   BIGINT,

    -- Common metadata
    tags              TEXT,
    context           TEXT,
    actor_id          INTEGER REFERENCES threat_actors(actor_id) ON DELETE SET NULL,
    reported_by       INTEGER REFERENCES ctims_users(user_id)    ON DELETE SET NULL,
    first_seen        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
--  TABLE 4: malware  (Ransomware, Trojan, Worm, Virus, etc.)
-- ============================================================
CREATE TABLE malware (
    malware_id       SERIAL PRIMARY KEY,
    malware_name     VARCHAR(100) NOT NULL,
    malware_family   VARCHAR(100),
    malware_type     VARCHAR(30)  NOT NULL
                     CHECK (malware_type IN ('Ransomware','Trojan','Worm','Virus',
                                             'Spyware','Rootkit','Adware','Botnet')),
    severity_score   DECIMAL(4,1) CHECK (severity_score BETWEEN 0.0 AND 10.0),
    target_platform  VARCHAR(50),
    description      TEXT,
    behavior         TEXT,
    mitigation       TEXT,
    actor_id         INTEGER REFERENCES threat_actors(actor_id) ON DELETE SET NULL,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
--  TABLE 5: malware_hashes  (Many-to-Many: malware ↔ hash IOC)
-- ============================================================
CREATE TABLE malware_hashes (
    malware_id   INTEGER REFERENCES malware(malware_id)    ON DELETE CASCADE,
    indicator_id INTEGER REFERENCES indicators(indicator_id) ON DELETE CASCADE,
    PRIMARY KEY (malware_id, indicator_id)         -- Composite Primary Key
);

-- ============================================================
--  TABLE 6: vulnerabilities  (CVE tracking)
-- ============================================================
CREATE TABLE vulnerabilities (
    vuln_id           SERIAL PRIMARY KEY,
    cve_id            VARCHAR(20) UNIQUE,           -- e.g., CVE-2024-1234
    title             VARCHAR(200) NOT NULL,
    description       TEXT,
    cvss_score        DECIMAL(4,1) CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    severity          VARCHAR(20) GENERATED ALWAYS AS (
                          CASE
                              WHEN cvss_score >= 9.0 THEN 'Critical'
                              WHEN cvss_score >= 7.0 THEN 'High'
                              WHEN cvss_score >= 4.0 THEN 'Medium'
                              ELSE 'Low'
                          END
                      ) STORED,                     -- Computed column
    affected_product  VARCHAR(200),
    affected_versions VARCHAR(200),
    is_patched        BOOLEAN DEFAULT FALSE,
    patch_available   BOOLEAN DEFAULT FALSE,
    exploit_available BOOLEAN DEFAULT FALSE,
    discovered_date   DATE,
    patch_date        DATE,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
--  TABLE 7: incidents  (Security Incidents)
-- ============================================================
CREATE TABLE incidents (
    incident_id       SERIAL PRIMARY KEY,
    incident_title    VARCHAR(200) NOT NULL,
    description       TEXT,
    severity          VARCHAR(20)  NOT NULL
                      CHECK (severity IN ('Critical','High','Medium','Low')),
    status            VARCHAR(30)  NOT NULL DEFAULT 'Open'
                      CHECK (status IN ('Open','In Progress','Resolved',
                                        'Closed','False Positive')),
    affected_systems  TEXT,
    impact_description TEXT,
    actor_id          INTEGER REFERENCES threat_actors(actor_id)  ON DELETE SET NULL,
    assigned_to       INTEGER REFERENCES ctims_users(user_id)     ON DELETE SET NULL,
    reported_by       INTEGER REFERENCES ctims_users(user_id)     ON DELETE SET NULL,
    discovered_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at       TIMESTAMP,
    resolution_notes  TEXT,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_resolution CHECK (resolved_at IS NULL OR resolved_at >= discovered_at)
);

-- ============================================================
--  TABLE 8: incident_indicators  (Many-to-Many: incidents ↔ IOC)
-- ============================================================
CREATE TABLE incident_indicators (
    incident_id  INTEGER REFERENCES incidents(incident_id)   ON DELETE CASCADE,
    indicator_id INTEGER REFERENCES indicators(indicator_id) ON DELETE CASCADE,
    added_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (incident_id, indicator_id)
);

-- ============================================================
--  TABLE 9: reports
-- ============================================================
CREATE TABLE reports (
    report_id    SERIAL PRIMARY KEY,
    report_title VARCHAR(200) NOT NULL,
    report_type  VARCHAR(50)
                 CHECK (report_type IN ('Threat Summary','Incident Report',
                                        'IOC Report','Actor Profile',
                                        'Vulnerability Assessment')),
    content      TEXT,
    generated_by INTEGER REFERENCES ctims_users(user_id) ON DELETE SET NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    period_start DATE,
    period_end   DATE
);

-- ============================================================
--  TABLE 10: audit_log  (Populated automatically by Triggers)
-- ============================================================
CREATE TABLE audit_log (
    log_id       SERIAL PRIMARY KEY,
    table_name   VARCHAR(50) NOT NULL,
    operation    VARCHAR(10) NOT NULL
                 CHECK (operation IN ('INSERT','UPDATE','DELETE')),
    record_id    INTEGER,
    old_data     TEXT,
    new_data     TEXT,
    performed_by VARCHAR(100),
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
--  ALTER TABLE examples (demonstrates ALTER command)
-- ============================================================
ALTER TABLE ctims_users  ADD COLUMN phone_number VARCHAR(20);
ALTER TABLE threat_actors ADD COLUMN active BOOLEAN DEFAULT TRUE;
ALTER TABLE indicators    ADD COLUMN reviewed BOOLEAN DEFAULT FALSE;

-- Comments on important columns
COMMENT ON COLUMN indicators.indicator_type IS 'IP=IP Address, Domain=Domain Name, URL=Uniform Resource Locator, Hash=File Hash';
COMMENT ON COLUMN vulnerabilities.severity  IS 'Auto-computed from cvss_score using CASE expression';
COMMENT ON TABLE  audit_log                 IS 'Populated automatically by database triggers — never insert manually';

SELECT 'Schema created successfully!' AS status;
