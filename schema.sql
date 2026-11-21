CREATE TABLE IF NOT EXISTS resources (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '其他',
  url TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '候选',
  summary TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS procedures (
  id SERIAL PRIMARY KEY,
  resource_id INT REFERENCES resources(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  recurrence TEXT NOT NULL DEFAULT 'daily',   -- daily | weekly | monthly | once
  open_url TEXT NOT NULL DEFAULT '',
  active BOOLEAN NOT NULL DEFAULT TRUE,
  sort INT NOT NULL DEFAULT 100,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS steps (
  id SERIAL PRIMARY KEY,
  procedure_id INT NOT NULL REFERENCES procedures(id) ON DELETE CASCADE,
  position INT NOT NULL,
  text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS completions (
  id SERIAL PRIMARY KEY,
  procedure_id INT NOT NULL REFERENCES procedures(id) ON DELETE CASCADE,
  period_key TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'manual',        -- manual | auto
  note TEXT NOT NULL DEFAULT '',
  done_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (procedure_id, period_key)
);
CREATE TABLE IF NOT EXISTS notes (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  pinned BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
