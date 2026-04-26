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

        self.ensure_column("trust_store", "domain_name", "TEXT")?;
        self.ensure_column("trust_store", "ca_cert_path", "TEXT")?;
        self.ensure_column("trust_store", "server_cert_path", "TEXT")?;
        self.ensure_column("trust_store", "client_cert_path", "TEXT")?;
        self.ensure_column("trust_store", "client_key_path", "TEXT")?;
        self.conn.execute_batch(
            "
            CREATE UNIQUE INDEX IF NOT EXISTS trust_store_identity_idx
            ON trust_store (deployment_id, instance_id, ip);
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

    pub fn record_deployment(
        &self,
        deployment_label: &str,
        instance_id: &str,
        server_ip: &str,
    ) -> rusqlite::Result<StoredDeployment> {
        let created_at = unix_now();
        self.conn.execute(
            "
            INSERT INTO deployments (deployment_label, instance_id, server_ip, created_at_unix)
            VALUES (?1, ?2, ?3, ?4)
            ",
            params![deployment_label, instance_id, server_ip, created_at],
        )?;
        Ok(StoredDeployment {
            id: self.conn.last_insert_rowid(),
            deployment_label: deployment_label.to_owned(),
            instance_id: instance_id.to_owned(),
            server_ip: server_ip.to_owned(),
            created_at_unix: created_at,
        })
    }

    pub fn latest_deployment(&self) -> rusqlite::Result<Option<StoredDeployment>> {
        let mut statement = self.conn.prepare(
            "
            SELECT id, deployment_label, instance_id, server_ip, created_at_unix
            FROM deployments
            ORDER BY id DESC
            LIMIT 1
            ",
        )?;
        let mut rows = statement.query([])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(StoredDeployment {
                id: row.get(0)?,
                deployment_label: row.get(1)?,
                instance_id: row.get(2)?,
                server_ip: row.get(3)?,
                created_at_unix: row.get(4)?,
            }));
        }
        Ok(None)
    }

    pub fn clear_deployment_by_instance(&self, instance_id: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM deployments WHERE instance_id = ?1",
            params![instance_id],
        )?;
        Ok(())
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

    pub fn upsert_trust_entry(
        &self,
        entry: NewTrustEntry<'_>,
    ) -> rusqlite::Result<StoredTrustEntry> {
        let updated_at = unix_now();
        self.conn.execute(
            "
            INSERT INTO trust_store (
                deployment_id,
                instance_id,
                ip,
                known_host_line,
                domain_name,
                ca_cert_path,
                server_cert_path,
                client_cert_path,
                client_key_path,
                updated_at_unix
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(deployment_id, instance_id, ip) DO UPDATE SET
                known_host_line = excluded.known_host_line,
                domain_name = excluded.domain_name,
                ca_cert_path = excluded.ca_cert_path,
                server_cert_path = excluded.server_cert_path,
                client_cert_path = excluded.client_cert_path,
                client_key_path = excluded.client_key_path,
                updated_at_unix = excluded.updated_at_unix
            ",
            params![
                entry.deployment_id,
                entry.instance_id,
                entry.ip,
                entry.known_host_line,
                entry.domain_name,
                entry.ca_cert_path,
                entry.server_cert_path,
                entry.client_cert_path,
                entry.client_key_path,
                updated_at,
            ],
        )?;

        self.get_trust_entry(entry.deployment_id, entry.instance_id, entry.ip)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn get_trust_entry(
        &self,
        deployment_id: &str,
        instance_id: &str,
        ip: &str,
    ) -> rusqlite::Result<Option<StoredTrustEntry>> {
        let mut statement = self.conn.prepare(
            "
            SELECT
                id,
                deployment_id,
                instance_id,
                ip,
                known_host_line,
                domain_name,
                ca_cert_path,
                server_cert_path,
                client_cert_path,
                client_key_path,
                updated_at_unix
            FROM trust_store
            WHERE deployment_id = ?1 AND instance_id = ?2 AND ip = ?3
            ",
        )?;
        let mut rows = statement.query(params![deployment_id, instance_id, ip])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(StoredTrustEntry {
                id: row.get(0)?,
                deployment_id: row.get(1)?,
                instance_id: row.get(2)?,
                ip: row.get(3)?,
                known_host_line: row.get(4)?,
                domain_name: row.get(5)?,
                ca_cert_path: row.get(6)?,
                server_cert_path: row.get(7)?,
                client_cert_path: row.get(8)?,
                client_key_path: row.get(9)?,
                updated_at_unix: row.get(10)?,
            }));
        }
        Ok(None)
    }

    pub fn list_trust_entries(&self) -> rusqlite::Result<Vec<StoredTrustEntry>> {
        let mut statement = self.conn.prepare(
            "
            SELECT
                id,
                deployment_id,
                instance_id,
                ip,
                known_host_line,
                domain_name,
                ca_cert_path,
                server_cert_path,
                client_cert_path,
                client_key_path,
                updated_at_unix
            FROM trust_store
            ORDER BY id ASC
            ",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(StoredTrustEntry {
                id: row.get(0)?,
                deployment_id: row.get(1)?,
                instance_id: row.get(2)?,
                ip: row.get(3)?,
                known_host_line: row.get(4)?,
                domain_name: row.get(5)?,
                ca_cert_path: row.get(6)?,
                server_cert_path: row.get(7)?,
                client_cert_path: row.get(8)?,
                client_key_path: row.get(9)?,
                updated_at_unix: row.get(10)?,
            })
        })?;

        rows.collect()
    }

    pub fn find_latest_trust_entry(
        &self,
        instance_id: &str,
        ip: &str,
    ) -> rusqlite::Result<Option<StoredTrustEntry>> {
        let mut statement = self.conn.prepare(
            "
            SELECT
                id,
                deployment_id,
                instance_id,
                ip,
                known_host_line,
                domain_name,
                ca_cert_path,
                server_cert_path,
                client_cert_path,
                client_key_path,
                updated_at_unix
            FROM trust_store
            WHERE instance_id = ?1 AND ip = ?2
            ORDER BY updated_at_unix DESC, id DESC
            LIMIT 1
            ",
        )?;
        let mut rows = statement.query(params![instance_id, ip])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(StoredTrustEntry {
                id: row.get(0)?,
                deployment_id: row.get(1)?,
                instance_id: row.get(2)?,
                ip: row.get(3)?,
                known_host_line: row.get(4)?,
                domain_name: row.get(5)?,
                ca_cert_path: row.get(6)?,
                server_cert_path: row.get(7)?,
                client_cert_path: row.get(8)?,
                client_key_path: row.get(9)?,
                updated_at_unix: row.get(10)?,
            }));
        }
        Ok(None)
    }

    pub fn clear_trust_entries(
        &self,
        instance_id: Option<&str>,
        ip: Option<&str>,
    ) -> rusqlite::Result<()> {
        if let Some(instance_id) = instance_id.filter(|value| !value.trim().is_empty()) {
            self.conn.execute(
                "DELETE FROM trust_store WHERE instance_id = ?1",
                params![instance_id],
            )?;
            return Ok(());
        }
        if let Some(ip) = ip.filter(|value| !value.trim().is_empty()) {
            self.conn
                .execute("DELETE FROM trust_store WHERE ip = ?1", params![ip])?;
        }
        Ok(())
    }

    fn ensure_column(
        &self,
        table_name: &str,
        column_name: &str,
        definition: &str,
    ) -> rusqlite::Result<()> {
        let pragma = format!("PRAGMA table_info({table_name})");
        let mut statement = self.conn.prepare(&pragma)?;
        let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
        for column in columns {
            if column? == column_name {
                return Ok(());
            }
        }

        let alter = format!("ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}");
        self.conn.execute(&alter, [])?;
        Ok(())
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

#[derive(Debug, Clone)]
pub struct StoredDeployment {
    pub id: i64,
    pub deployment_label: String,
    pub instance_id: String,
    pub server_ip: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct NewTrustEntry<'a> {
    pub deployment_id: &'a str,
    pub instance_id: &'a str,
    pub ip: &'a str,
    pub known_host_line: &'a str,
    pub domain_name: Option<&'a str>,
    pub ca_cert_path: Option<&'a str>,
    pub server_cert_path: Option<&'a str>,
    pub client_cert_path: Option<&'a str>,
    pub client_key_path: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct StoredTrustEntry {
    pub id: i64,
    pub deployment_id: String,
    pub instance_id: String,
    pub ip: String,
    pub known_host_line: String,
    pub domain_name: Option<String>,
    pub ca_cert_path: Option<String>,
    pub server_cert_path: Option<String>,
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub updated_at_unix: i64,
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
        let trust = state
            .upsert_trust_entry(NewTrustEntry {
                deployment_id: "deploy-1",
                instance_id: "instance-1",
                ip: "203.0.113.10",
                known_host_line: "",
                domain_name: Some("edge-agent"),
                ca_cert_path: Some("/tmp/ca.pem"),
                server_cert_path: Some("/tmp/agent-server.pem"),
                client_cert_path: Some("/tmp/controller-client.pem"),
                client_key_path: Some("/tmp/controller-client.key"),
            })
            .unwrap();
        assert_eq!(trust.domain_name.as_deref(), Some("edge-agent"));
        assert_eq!(
            trust.client_key_path.as_deref(),
            Some("/tmp/controller-client.key")
        );
        let latest_trust = state
            .find_latest_trust_entry("instance-1", "203.0.113.10")
            .unwrap()
            .unwrap();
        assert_eq!(latest_trust.deployment_id, "deploy-1");
        assert_eq!(state.list_trust_entries().unwrap().len(), 1);
        let deployment = state
            .record_deployment("deploy-1", "instance-1", "203.0.113.10")
            .unwrap();
        assert_eq!(deployment.server_ip, "203.0.113.10");
        assert_eq!(
            state.latest_deployment().unwrap().unwrap().instance_id,
            "instance-1"
        );
        state.clear_deployment_by_instance("instance-1").unwrap();
        assert!(state.latest_deployment().unwrap().is_none());
        state
            .clear_trust_entries(Some("instance-1"), Some("203.0.113.10"))
            .unwrap();
        assert!(state.list_trust_entries().unwrap().is_empty());
        let _ = std::fs::remove_file(db_path);
    }
}
