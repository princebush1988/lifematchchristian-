-- Life Match Christian — Postgres schema (also created automatically by server.js on boot)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  pin_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  age INT NOT NULL CHECK (age >= 18),
  gender TEXT NOT NULL,
  looking_for TEXT NOT NULL DEFAULT 'everyone',
  country TEXT NOT NULL,
  city TEXT NOT NULL DEFAULT '',
  church TEXT NOT NULL DEFAULT '',
  faith_story TEXT NOT NULL DEFAULT '',
  photo_url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected | blocked
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS likes (
  id SERIAL PRIMARY KEY,
  liker_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  liked BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (liker_id, target_id)
);
CREATE TABLE IF NOT EXISTS matches (
  id SERIAL PRIMARY KEY,
  user_a INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_a, user_b)
);
CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  match_id INT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'text', -- text | verse | prayer
  is_read BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS typing_states (
  match_id INT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  is_typing BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (match_id, user_id)
);
CREATE TABLE IF NOT EXISTS call_signals (
  id SERIAL PRIMARY KEY,
  match_id INT NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  sender_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL, -- offer | answer | ice | ring | end
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_match ON messages(match_id, created_at);
CREATE INDEX IF NOT EXISTS idx_signals_match ON call_signals(match_id, created_at);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
