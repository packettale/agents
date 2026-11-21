CREATE TABLE IF NOT EXISTS management.capture (
 id INTEGER PRIMARY KEY, device_id TEXT NOT NULL UNIQUE, stream_id TEXT NOT NULL,
 started_at INTEGER NOT NULL, sequence INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS management.one_active_capture ON capture(active) WHERE active=1;
CREATE TABLE IF NOT EXISTS management.hours (
 capture_id INTEGER NOT NULL, hour INTEGER NOT NULL,
 allowed INTEGER NOT NULL DEFAULT 0 CHECK(typeof(allowed)='integer' AND allowed>=0),
 blocked INTEGER NOT NULL DEFAULT 0 CHECK(typeof(blocked)='integer' AND blocked>=0),
 dns INTEGER NOT NULL DEFAULT 0 CHECK(typeof(dns)='integer' AND dns>=0),
 bytes_sent INTEGER NOT NULL DEFAULT 0 CHECK(typeof(bytes_sent)='integer' AND bytes_sent>=0),
 bytes_received INTEGER NOT NULL DEFAULT 0 CHECK(typeof(bytes_received)='integer' AND bytes_received>=0),
 PRIMARY KEY(capture_id,hour)
);
CREATE TABLE IF NOT EXISTS management.destinations (
 capture_id INTEGER NOT NULL, day TEXT NOT NULL, profile_id TEXT NOT NULL, app TEXT NOT NULL, host TEXT NOT NULL, country TEXT NOT NULL DEFAULT '',
 allowed INTEGER NOT NULL DEFAULT 0 CHECK(typeof(allowed)='integer' AND allowed>=0),
 blocked INTEGER NOT NULL DEFAULT 0 CHECK(typeof(blocked)='integer' AND blocked>=0),
 bytes_sent INTEGER NOT NULL DEFAULT 0 CHECK(typeof(bytes_sent)='integer' AND bytes_sent>=0),
 bytes_received INTEGER NOT NULL DEFAULT 0 CHECK(typeof(bytes_received)='integer' AND bytes_received>=0),
 PRIMARY KEY(capture_id,day,profile_id,app,host,country)
);
CREATE TABLE IF NOT EXISTS management.outbox (
 capture_id INTEGER PRIMARY KEY, sequence INTEGER NOT NULL, body BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS management.categories (
 capture_id INTEGER NOT NULL,day TEXT NOT NULL,profile_id TEXT NOT NULL,host TEXT NOT NULL,country TEXT NOT NULL,lists TEXT NOT NULL,
 blocked INTEGER NOT NULL DEFAULT 0 CHECK(typeof(blocked)='integer' AND blocked>=0),
 PRIMARY KEY(capture_id,day,profile_id,host,country,lists)
);
