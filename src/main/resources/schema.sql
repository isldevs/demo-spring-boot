-- Users table
CREATE TABLE IF NOT EXISTS users
(
    id       BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(200) NOT NULL,
    enabled  BOOLEAN      NOT NULL
);

-- Roles table
CREATE TABLE IF NOT EXISTS roles
(
    id   BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

-- Authorities table
CREATE TABLE IF NOT EXISTS authorities
(
    id   BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

-- User-Roles mapping
CREATE TABLE IF NOT EXISTS user_roles
(
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Role-Authorities mapping
CREATE TABLE IF NOT EXISTS role_authorities
(
    role_id      BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    authority_id BIGINT NOT NULL REFERENCES authorities (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, authority_id)
);


-- OAuth2 Registered Clients (Spring Authorization Server)
CREATE TABLE IF NOT EXISTS oauth2_registered_client
(
    id                            VARCHAR(100) PRIMARY KEY,
    client_id                     VARCHAR(100)  NOT NULL,
    client_id_issued_at           TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_secret                 VARCHAR(200),
    client_secret_expires_at      TIMESTAMP,
    client_name                   VARCHAR(200)  NOT NULL,
    client_authentication_methods VARCHAR(1000) NOT NULL,
    authorization_grant_types     VARCHAR(1000) NOT NULL,
    redirect_uris                 VARCHAR(1000),
    post_logout_redirect_uris     VARCHAR(1000),
    scopes                        VARCHAR(1000) NOT NULL,
    client_settings               VARCHAR(2000) NOT NULL,
    token_settings                VARCHAR(2000) NOT NULL
);

-- OAuth2 Authorization table
CREATE TABLE IF NOT EXISTS oauth2_authorization
(
    id                            VARCHAR(100) PRIMARY KEY,
    registered_client_id          VARCHAR(100) NOT NULL REFERENCES oauth2_registered_client (id),
    principal_name                VARCHAR(200) NOT NULL,
    authorization_grant_type      VARCHAR(100) NOT NULL,
    authorized_scopes             VARCHAR(1000),
    attributes                    BYTEA,
    state                         VARCHAR(500),
    authorization_code_value      BYTEA,
    authorization_code_issued_at  TIMESTAMP,
    authorization_code_expires_at TIMESTAMP,
    authorization_code_metadata   BYTEA,
    access_token_value            BYTEA,
    access_token_issued_at        TIMESTAMP,
    access_token_expires_at       TIMESTAMP,
    access_token_metadata         BYTEA,
    access_token_type             VARCHAR(100),
    access_token_scopes           VARCHAR(1000),
    oidc_id_token_value           BYTEA,
    oidc_id_token_issued_at       TIMESTAMP,
    oidc_id_token_expires_at      TIMESTAMP,
    oidc_id_token_metadata        BYTEA,
    refresh_token_value           BYTEA,
    refresh_token_issued_at       TIMESTAMP,
    refresh_token_expires_at      TIMESTAMP,
    refresh_token_metadata        BYTEA
);

-- ---------------------------
-- Authorities
-- ---------------------------
INSERT INTO authorities(name) VALUES ('READ_PRIVILEGE') ON CONFLICT DO NOTHING;
INSERT INTO authorities(name) VALUES ('WRITE_PRIVILEGE') ON CONFLICT DO NOTHING;
INSERT INTO authorities(name) VALUES ('DELETE_PRIVILEGE') ON CONFLICT DO NOTHING;

-- ---------------------------
-- Roles
-- ---------------------------
INSERT INTO roles(name) VALUES ('ROLE_ADMIN') ON CONFLICT DO NOTHING;
INSERT INTO roles(name) VALUES ('ROLE_USER') ON CONFLICT DO NOTHING;

-- ---------------------------
-- Role -> Authorities mapping
-- ---------------------------
-- Get IDs dynamically
-- ROLE_USER -> READ_PRIVILEGE
INSERT INTO role_authorities(role_id, authority_id) SELECT r.id, a.id
FROM roles r, authorities a
WHERE r.name = 'ROLE_USER'
  AND a.name = 'READ_PRIVILEGE'
ON CONFLICT DO NOTHING;

-- ROLE_ADMIN -> READ_PRIVILEGE, WRITE_PRIVILEGE, DELETE_PRIVILEGE
INSERT INTO role_authorities(role_id, authority_id)
SELECT r.id, a.id
FROM roles r,
     authorities a
WHERE r.name = 'ROLE_ADMIN'
  AND a.name IN ('READ_PRIVILEGE', 'WRITE_PRIVILEGE', 'DELETE_PRIVILEGE')
ON CONFLICT DO NOTHING;

-- ---------------------------
-- Default Admin User
-- ---------------------------
INSERT INTO users(username, password, enabled)
VALUES ('admin',
        '{bcrypt}$2a$10$7sPC8bG3Qz4zH8MAB3xmuOqA89QpoQtEV9Tq4s7lE5TrfOi/yDg1K', -- BCrypt: password
        true)
ON CONFLICT DO NOTHING;

-- ---------------------------
-- Admin User -> ROLE_ADMIN
-- ---------------------------
INSERT INTO user_roles(user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin'
  AND r.name = 'ROLE_ADMIN'
ON CONFLICT DO NOTHING;
