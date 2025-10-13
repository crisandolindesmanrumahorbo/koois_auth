CREATE USER koois_user WITH ENCRYPTED PASSWORD 'password';
DROP DATABASE IF EXISTS koois_db;
CREATE DATABASE koois_db;
GRANT ALL PRIVILEGES ON DATABASE koois_db TO koois_user;

CREATE TABLE permissions (
	permission_id SERIAL PRIMARY KEY,
	name VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE roles (
	role_id SERIAL PRIMARY KEY,
	name VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE role_permissions (
	role_id INT NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
  permission_id INT NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);


CREATE TABLE users (
	user_id SERIAL PRIMARY KEY,
	username VARCHAR(50) UNIQUE NOT NULL,
	password TEXT,
  email VARCHAR(255) UNIQUE,
  provider VARCHAR(30) NOT NULL,
  provider_id TEXT,                                
  role_id INT NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);


