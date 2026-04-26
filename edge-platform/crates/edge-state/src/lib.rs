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

    pub fn start_operation(&self, kind: &str, status: &str) -> rusqlite::Result<StoredOperation> {
        let created_at = unix_now();
        self.conn.execute(
            "
            INSERT INTO operations (kind, status, created_at_unix)
            VALUES (?1, ?2, ?3)
            ",
            params![kind, status, created_at],
        )?;
        let id = self.conn.last_insert_rowid();
        Ok(StoredOperation {
            id,
            kind: kind.to_owned(),
            status: status.to_owned(),
            created_at_unix: created_at,
        })
    }

    pub fn update_operation_status(&self, operation_id: i64, status: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE operations SET status = ?2 WHERE id = ?1",
            params![operation_id, status],
        )?;
        Ok(())
    }

    pub fn append_operation_event(
        &self,
        operation_id: i64,
        message: &str,
    ) -> rusqlite::Result<StoredOperationEvent> {
        let created_at = unix_now();
        self.conn.execute(
            "
            INSERT INTO operation_events (operation_id, message, created_at_unix)
            VALUES (?1, ?2, ?3)
            ",
            params![operation_id, message, created_at],
        )?;
        Ok(StoredOperationEvent {
            id: self.conn.last_insert_rowid(),
            operation_id,
            message: message.to_owned(),
            created_at_unix: created_at,
        })
    }

    pub fn get_operation(&self, operation_id: i64) -> rusqlite::Result<Option<StoredOperation>> {
        let mut statement = self
            .conn
            .prepare("SELECT id, kind, status, created_at_unix FROM operations WHERE id = ?1")?;
        let mut rows = statement.query(params![operation_id])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(StoredOperation {
                id: row.get(0)?,
                kind: row.get(1)?,
                status: row.get(2)?,
                created_at_unix: row.get(3)?,
            }));
        }
        Ok(None)
    }

    pub fn list_operation_events(
        &self,
        operation_id: i64,
    ) -> rusqlite::Result<Vec<StoredOperationEvent>> {
        let mut statement = self.conn.prepare(
            "
            SELECT id, operation_id, message, created_at_unix
            FROM operation_events
            WHERE operation_id = ?1
            ORDER BY id ASC
            ",
        )?;
        let rows = statement.query_map(params![operation_id], |row| {
            Ok(StoredOperationEvent {
                id: row.get(0)?,
                operation_id: row.get(1)?,
                message: row.get(2)?,
                created_at_unix: row.get(3)?,
            })
        })?;

        rows.collect()
    }
}

#[derive(Debug, Clone)]
pub struct StoredOperation {
    pub id: i64,
    pub kind: String,
    pub status: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct StoredOperationEvent {
    pub id: i64,
    pub operation_id: i64,
    pub message: String,
    pub created_at_unix: i64,
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
        let operation = state
            .start_operation("start_local_runtime", "RUNNING")
            .unwrap();
        state
            .append_operation_event(operation.id, "starting local runtime")
            .unwrap();
        state
            .update_operation_status(operation.id, "SUCCEEDED")
            .unwrap();
        let stored = state.get_operation(operation.id).unwrap().unwrap();
        assert_eq!(stored.status, "SUCCEEDED");
        assert_eq!(state.list_operation_events(operation.id).unwrap().len(), 1);
        let _ = std::fs::remove_file(db_path);
    }
}
