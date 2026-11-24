-- Stella Maris portal database schema (Cloudflare D1)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role IN ('admin','teacher')),
  username TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS classes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS subjects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS terms (
  name TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS teacher_subjects (
  user_id TEXT NOT NULL REFERENCES users(id),
  subject_id TEXT NOT NULL REFERENCES subjects(id),
  PRIMARY KEY (user_id, subject_id)
);
CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  adm TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  class_id TEXT NOT NULL REFERENCES classes(id),
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS marks (
  student_id TEXT NOT NULL REFERENCES students(id),
  subject_id TEXT NOT NULL REFERENCES subjects(id),
  term TEXT NOT NULL REFERENCES terms(name),
  class_id TEXT NOT NULL REFERENCES classes(id),
  score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  teacher_id TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (student_id, subject_id, term)
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  account_type TEXT NOT NULL,
  account_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
