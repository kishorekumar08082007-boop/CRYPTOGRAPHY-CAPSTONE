-- Digital Signature System Database Schema
CREATE DATABASE IF NOT EXISTS digital_signature_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE digital_signature_system;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active TINYINT(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS certificates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    certificate_serial VARCHAR(64) NOT NULL UNIQUE,
    public_key LONGTEXT NOT NULL,
    certificate_data LONGTEXT NOT NULL,
    issue_date DATETIME NOT NULL,
    expiry_date DATETIME NOT NULL,
    status ENUM('active', 'revoked', 'expired') NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    document_name VARCHAR(255) NOT NULL,
    stored_file_path VARCHAR(500) NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    digital_signature LONGTEXT NOT NULL,
    certificate_id INT NOT NULL,
    signed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    file_size INT NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS verification_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    document_id INT,
    verified_by INT NOT NULL,
    verification_status ENUM('valid', 'invalid', 'tampered') NOT NULL,
    verification_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT,
    uploaded_file_hash VARCHAR(64),
    FOREIGN KEY (document_id) REFERENCES documents(id) ON DELETE SET NULL,
    FOREIGN KEY (verified_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
