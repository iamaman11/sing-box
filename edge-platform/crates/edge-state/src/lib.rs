use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

pub struct EdgeState {
    conn: Connection,
}

impl EdgeState {
    pub fn open_or_create(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let conn = Connection::open(path)?;
        let state = Self { conn };
        state.run_migrations()?;
        Ok(state)
    }

    pub fn run_migrations(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY,
                deployment_label TEXT,
                instance_id TEXT,
                server_ip TEXT,
                created_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operations (
                id INTEGER PRIMARY KEY,
                kind TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operation_events (
                id INTEGER PRIMARY KEY,
                operation_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS desired_state (
                key TEXT PRIMARY KEY,
                value_blob BLOB NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS provider_observations (
                id INTEGER PRIMARY KEY,
                payload BLOB NOT NULL,
                observed_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS server_observations (
                id INTEGER PRIMARY KEY,
                payload BLOB NOT NULL,
                observed_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS local_observations (
                observation_kind TEXT PRIMARY KEY,
                payload BLOB NOT NULL,
                observed_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secret_refs (
                name TEXT PRIMARY KEY,
                secret_ref TEXT NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trust_store (
                id INTEGER PRIMARY KEY,
                deployment_id TEXT,
                instance_id TEXT,
                ip TEXT NOT NULL,
                known_host_line TEXT NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS config_sync_runs (
                id INTEGER PRIMARY KEY,
                status TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL
            );
            ",
        )?;

        Ok(())
    }

    pub fn store_local_observation(
        &self,
        observation_kind: &str,
        payload: &[u8],
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "
            INSERT INTO local_observations (observation_kind, payload, observed_at_unix)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(observation_kind) DO UPDATE SET
                payload = excluded.payload,
                observed_at_unix = excluded.observed_at_unix
            ",
            params![observation_kind, payload, unix_now()],
        )?;

        Ok(())
    }

    pub fn local_observation_count(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM local_observations", [], |row| {
                row.get(0)
            })
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initializes_schema_and_stores_observation() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-state-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = EdgeState::open_or_create(&db_path).unwrap();
        state
            .store_local_observation("controller_status", &[1, 2, 3])
            .unwrap();
        assert_eq!(state.local_observation_count().unwrap(), 1);
        let _ = std::fs::remove_file(db_path);
    }
}
