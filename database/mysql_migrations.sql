-- =====================================================================
-- PhishGuard - MySQL schema (generated from the Alembic migrations)
--
-- Preferred:   set DATABASE_URL in .env and run   flask --app run db upgrade
-- Alternative: run this file manually, e.g.
--              mysql -u root -p < database/mysql_migrations.sql
--
-- Regenerate after adding a migration:
--   DATABASE_URL=mysql+pymysql://u:p@localhost/phishguard \
--   flask --app run db upgrade --sql > database/mysql_migrations.sql
-- =====================================================================
CREATE DATABASE IF NOT EXISTS phishguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE phishguard;

CREATE TABLE alembic_version (
    version_num VARCHAR(32) NOT NULL, 
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);

-- Running upgrade  -> 099a905c0aa9

CREATE TABLE awareness_articles (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    title VARCHAR(150) NOT NULL, 
    slug VARCHAR(160) NOT NULL, 
    category VARCHAR(50) NOT NULL, 
    icon VARCHAR(40) NOT NULL, 
    summary VARCHAR(300) NOT NULL, 
    content TEXT NOT NULL, 
    published BOOL NOT NULL, 
    position INTEGER NOT NULL, 
    views INTEGER NOT NULL, 
    created_at DATETIME NOT NULL, 
    updated_at DATETIME NOT NULL, 
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ix_awareness_articles_slug ON awareness_articles (slug);

CREATE TABLE users (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    username VARCHAR(40) NOT NULL, 
    email VARCHAR(120) NOT NULL, 
    full_name VARCHAR(100), 
    password_hash VARCHAR(255) NOT NULL, 
    is_admin BOOL NOT NULL, 
    active BOOL NOT NULL, 
    failed_logins INTEGER NOT NULL, 
    locked_until DATETIME, 
    created_at DATETIME NOT NULL, 
    last_login DATETIME, 
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE UNIQUE INDEX ix_users_username ON users (username);

CREATE TABLE activity_logs (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    user_id INTEGER, 
    action VARCHAR(50) NOT NULL, 
    detail VARCHAR(500), 
    ip_address VARCHAR(45), 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_activity_logs_action ON activity_logs (action);

CREATE INDEX ix_activity_logs_created_at ON activity_logs (created_at);

CREATE INDEX ix_activity_logs_user_id ON activity_logs (user_id);

CREATE TABLE scans (
    id INTEGER NOT NULL AUTO_INCREMENT, 
    user_id INTEGER, 
    url TEXT NOT NULL, 
    normalised_url TEXT NOT NULL, 
    domain VARCHAR(255) NOT NULL, 
    classification VARCHAR(20) NOT NULL, 
    score INTEGER NOT NULL, 
    rule_score INTEGER NOT NULL, 
    ml_probability FLOAT, 
    reasons JSON NOT NULL, 
    good_signs JSON NOT NULL, 
    notes JSON NOT NULL, 
    features JSON NOT NULL, 
    source VARCHAR(10) NOT NULL, 
    created_at DATETIME NOT NULL, 
    PRIMARY KEY (id), 
    FOREIGN KEY(user_id) REFERENCES users (id)
);

CREATE INDEX ix_scans_classification ON scans (classification);

CREATE INDEX ix_scans_created_at ON scans (created_at);

CREATE INDEX ix_scans_domain ON scans (domain);

CREATE INDEX ix_scans_user_id ON scans (user_id);

INSERT INTO alembic_version (version_num) VALUES ('099a905c0aa9');

