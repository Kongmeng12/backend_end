-- ================================================================
-- schema.sql — Booking System Database Setup
-- ລັນ: mysql -u root -p < schema.sql
-- ================================================================

CREATE DATABASE IF NOT EXISTS booking_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE booking_system;

-- ----------------------------------------------------------------
-- 1. roles
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS roles (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(50) NOT NULL UNIQUE,
    permissions JSON,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------
-- 2. users
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    role_id       INT NOT NULL DEFAULT 3,
    name          VARCHAR(100) NOT NULL,
    email         VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    phone         VARCHAR(20),
    is_active     TINYINT(1) DEFAULT 1,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- ----------------------------------------------------------------
-- 3. animals
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS animals (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    owner_id   INT NOT NULL,
    name       VARCHAR(100) NOT NULL,
    species    VARCHAR(50) NOT NULL,
    breed      VARCHAR(100),
    age        INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id)
);

-- ----------------------------------------------------------------
-- 4. services
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS services (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    price       DECIMAL(10,2) NOT NULL,
    is_active   TINYINT(1) DEFAULT 1,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ----------------------------------------------------------------
-- 5. bookings
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS bookings (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    animal_id      INT NOT NULL,
    service_id     INT NOT NULL,
    scheduled_date DATE NOT NULL,
    status         ENUM('pending','confirmed','in_progress','completed','cancelled') DEFAULT 'pending',
    note           TEXT,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)    REFERENCES users(id),
    FOREIGN KEY (animal_id)  REFERENCES animals(id),
    FOREIGN KEY (service_id) REFERENCES services(id)
);

-- ----------------------------------------------------------------
-- 6. payments
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS payments (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    booking_id  INT NOT NULL,
    type        ENUM('deposit','full') DEFAULT 'full',
    amount      DECIMAL(10,2) NOT NULL,
    slip_url    VARCHAR(500),
    status      ENUM('pending','approved','rejected') DEFAULT 'pending',
    approved_by INT,
    paid_at     TIMESTAMP NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id)  REFERENCES bookings(id),
    FOREIGN KEY (approved_by) REFERENCES users(id)
);

-- ----------------------------------------------------------------
-- 7. receipts
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS receipts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    booking_id    INT NOT NULL,
    total_amount  DECIMAL(10,2) NOT NULL,
    deposit_paid  DECIMAL(10,2) DEFAULT 0,
    issued_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(id)
);

-- ----------------------------------------------------------------
-- 8. notifications
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notifications (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT NOT NULL,
    booking_id INT,
    message    TEXT NOT NULL,
    type       ENUM('info','warning','success','error') DEFAULT 'info',
    is_read    TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)    REFERENCES users(id),
    FOREIGN KEY (booking_id) REFERENCES bookings(id)
);

-- ----------------------------------------------------------------
-- 9. reports
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    generated_by INT NOT NULL,
    report_type  VARCHAR(50) DEFAULT 'custom',
    period_start DATE NOT NULL,
    period_end   DATE NOT NULL,
    data         JSON,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (generated_by) REFERENCES users(id)
);

-- ----------------------------------------------------------------
-- Seed Data — roles ເລີ່ມຕົ້ນ
-- ----------------------------------------------------------------
INSERT IGNORE INTO roles (id, name, permissions) VALUES
    (1, 'admin', '["all"]'),
    (2, 'staff', '["bookings","payments","receipts"]'),
    (3, 'customer', '["bookings.own","animals.own"]');
