use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use edge_shared_types::{AppReadinessPhase, DeployPhase};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, params};

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

            CREATE TABLE IF NOT EXISTS controller_state (
                singleton_key INTEGER PRIMARY KEY CHECK (singleton_key = 1),
                active_deployment_label TEXT,
                active_instance_id TEXT,
                active_server_ip TEXT,
                active_tunnel_domain TEXT,
                active_deployment_state_json TEXT,
                deploy_phase TEXT NOT NULL,
                app_readiness_phase TEXT NOT NULL,
                last_error_code TEXT,
                last_error_message TEXT,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS selector_intents (
                group_name TEXT PRIMARY KEY,
                desired_route TEXT NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );
            ",
        )?;

        self.ensure_column("trust_store", "domain_name", "TEXT")?;
        self.ensure_column("trust_store", "ca_cert_path", "TEXT")?;
        self.ensure_column("trust_store", "server_cert_path", "TEXT")?;
        self.ensure_column("trust_store", "client_cert_path", "TEXT")?;
        self.ensure_column("trust_store", "client_key_path", "TEXT")?;
        self.ensure_column("controller_state", "active_deployment_state_json", "TEXT")?;
        self.conn.execute_batch(
            "
            CREATE UNIQUE INDEX IF NOT EXISTS trust_store_identity_idx
            ON trust_store (deployment_id, instance_id, ip);
            ",
        )?;
        self.conn.execute(
            "
            INSERT INTO controller_state (
                singleton_key,
                deploy_phase,
                app_readiness_phase,
                updated_at_unix
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(singleton_key) DO NOTHING
            ",
            params![
                1,
                deploy_phase_storage_name(DeployPhase::Unspecified),
                app_readiness_phase_storage_name(AppReadinessPhase::DeploymentAbsent),
                unix_now()
            ],
        )?;
        // `desired_state` was a legacy table from an older controller model.
        // Drop it so diagnostics cannot drift from the true SQLite state.
        self.conn
            .execute("DROP TABLE IF EXISTS desired_state", [])?;

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

    pub fn upsert_controller_state(
        &self,
        state: NewControllerState<'_>,
    ) -> rusqlite::Result<StoredControllerState> {
        let updated_at = unix_now();
        self.conn.execute(
            "
            INSERT INTO controller_state (
                singleton_key,
                active_deployment_label,
                active_instance_id,
                active_server_ip,
                active_tunnel_domain,
                active_deployment_state_json,
                deploy_phase,
                app_readiness_phase,
                last_error_code,
                last_error_message,
                updated_at_unix
            )
            VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(singleton_key) DO UPDATE SET
                active_deployment_label = excluded.active_deployment_label,
                active_instance_id = excluded.active_instance_id,
                active_server_ip = excluded.active_server_ip,
                active_tunnel_domain = excluded.active_tunnel_domain,
                active_deployment_state_json = excluded.active_deployment_state_json,
                deploy_phase = excluded.deploy_phase,
                app_readiness_phase = excluded.app_readiness_phase,
                last_error_code = excluded.last_error_code,
                last_error_message = excluded.last_error_message,
                updated_at_unix = excluded.updated_at_unix
            ",
            params![
                state.active_deployment_label,
                state.active_instance_id,
                state.active_server_ip,
                state.active_tunnel_domain,
                state.active_deployment_state_json,
                deploy_phase_storage_name(state.deploy_phase),
                app_readiness_phase_storage_name(state.app_readiness_phase),
                state.last_error_code,
                state.last_error_message,
                updated_at,
            ],
        )?;
        self.get_controller_state()?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn get_controller_state(&self) -> rusqlite::Result<Option<StoredControllerState>> {
        self.conn
            .query_row(
                "
                SELECT
                    active_deployment_label,
                    active_instance_id,
                    active_server_ip,
                    active_tunnel_domain,
                    active_deployment_state_json,
                    deploy_phase,
                    app_readiness_phase,
                    last_error_code,
                    last_error_message,
                    updated_at_unix
                FROM controller_state
                WHERE singleton_key = 1
                ",
                [],
                |row| {
                    Ok(StoredControllerState {
                        active_deployment_label: row.get(0)?,
                        active_instance_id: row.get(1)?,
                        active_server_ip: row.get(2)?,
                        active_tunnel_domain: row.get(3)?,
                        active_deployment_state_json: row.get(4)?,
                        deploy_phase: parse_deploy_phase_storage_value(row.get(5)?)?,
                        app_readiness_phase: parse_app_readiness_phase_storage_value(row.get(6)?)?,
                        last_error_code: row.get(7)?,
                        last_error_message: row.get(8)?,
                        updated_at_unix: row.get(9)?,
                    })
                },
            )
            .optional()
    }

    pub fn clear_controller_state(&self) -> rusqlite::Result<()> {
        self.conn.execute(
            "
            UPDATE controller_state
            SET
                active_deployment_label = NULL,
                active_instance_id = NULL,
                active_server_ip = NULL,
                active_tunnel_domain = NULL,
                active_deployment_state_json = NULL,
                deploy_phase = ?2,
                app_readiness_phase = ?3,
                last_error_code = NULL,
                last_error_message = NULL,
                updated_at_unix = ?1
            WHERE singleton_key = 1
            ",
            params![
                unix_now(),
                deploy_phase_storage_name(DeployPhase::Unspecified),
                app_readiness_phase_storage_name(AppReadinessPhase::DeploymentAbsent)
            ],
        )?;
        Ok(())
    }

    pub fn upsert_selector_intent(
        &self,
        group_name: &str,
        desired_route: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "
            INSERT INTO selector_intents (group_name, desired_route, updated_at_unix)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(group_name) DO UPDATE SET
                desired_route = excluded.desired_route,
                updated_at_unix = excluded.updated_at_unix
            ",
            params![group_name, desired_route, unix_now()],
        )?;
        Ok(())
    }

    pub fn get_selector_intent(
        &self,
        group_name: &str,
    ) -> rusqlite::Result<Option<StoredSelectorIntent>> {
        self.conn
            .query_row(
                "
                SELECT group_name, desired_route, updated_at_unix
                FROM selector_intents
                WHERE group_name = ?1
                ",
                params![group_name],
                |row| {
                    Ok(StoredSelectorIntent {
                        group_name: row.get(0)?,
                        desired_route: row.get(1)?,
                        updated_at_unix: row.get(2)?,
                    })
                },
            )
            .optional()
    }

    pub fn list_selector_intents(&self) -> rusqlite::Result<Vec<StoredSelectorIntent>> {
        let mut statement = self.conn.prepare(
            "
            SELECT group_name, desired_route, updated_at_unix
            FROM selector_intents
            ORDER BY group_name ASC
            ",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(StoredSelectorIntent {
                group_name: row.get(0)?,
                desired_route: row.get(1)?,
                updated_at_unix: row.get(2)?,
            })
        })?;
        rows.collect()
    }

    pub fn upsert_secret_ref(&self, name: &str, secret_ref: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "
            INSERT INTO secret_refs (name, secret_ref, updated_at_unix)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(name) DO UPDATE SET
                secret_ref = excluded.secret_ref,
                updated_at_unix = excluded.updated_at_unix
            ",
            params![name, secret_ref, unix_now()],
        )?;
        Ok(())
    }

    pub fn get_secret_ref(&self, name: &str) -> rusqlite::Result<Option<StoredSecretRef>> {
        let mut statement = self.conn.prepare(
            "
            SELECT name, secret_ref, updated_at_unix
            FROM secret_refs
            WHERE name = ?1
            ",
        )?;
        let mut rows = statement.query(params![name])?;
        if let Some(row) = rows.next()? {
            return Ok(Some(StoredSecretRef {
                name: row.get(0)?,
                secret_ref: row.get(1)?,
                updated_at_unix: row.get(2)?,
            }));
        }
        Ok(None)
    }

    pub fn list_secret_refs(&self) -> rusqlite::Result<Vec<StoredSecretRef>> {
        let mut statement = self.conn.prepare(
            "
            SELECT name, secret_ref, updated_at_unix
            FROM secret_refs
            ORDER BY name ASC
            ",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(StoredSecretRef {
                name: row.get(0)?,
                secret_ref: row.get(1)?,
                updated_at_unix: row.get(2)?,
            })
        })?;

        rows.collect()
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

    pub fn find_deployment_by_instance(
        &self,
        instance_id: &str,
    ) -> rusqlite::Result<Option<StoredDeployment>> {
        let mut statement = self.conn.prepare(
            "
            SELECT id, deployment_label, instance_id, server_ip, created_at_unix
            FROM deployments
            WHERE instance_id = ?1
            ORDER BY id DESC
            LIMIT 1
            ",
        )?;
        let mut rows = statement.query(params![instance_id])?;
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

    pub fn clear_deployment_by_label(&self, deployment_label: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM deployments WHERE deployment_label = ?1",
            params![deployment_label],
        )?;
        Ok(())
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

    pub fn latest_operation_by_kind(
        &self,
        kind: &str,
    ) -> rusqlite::Result<Option<StoredOperation>> {
        let mut statement = self.conn.prepare(
            "
            SELECT id, kind, status, created_at_unix
            FROM operations
            WHERE kind = ?1
            ORDER BY id DESC
            LIMIT 1
            ",
        )?;
        let mut rows = statement.query(params![kind])?;
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

    pub fn list_operations_by_status(
        &self,
        status: &str,
    ) -> rusqlite::Result<Vec<StoredOperation>> {
        let mut statement = self.conn.prepare(
            "
            SELECT id, kind, status, created_at_unix
            FROM operations
            WHERE status = ?1
            ORDER BY id ASC
            ",
        )?;
        let rows = statement.query_map(params![status], |row| {
            Ok(StoredOperation {
                id: row.get(0)?,
                kind: row.get(1)?,
                status: row.get(2)?,
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

    pub fn clear_trust_entry(
        &self,
        deployment_id: &str,
        instance_id: &str,
        ip: &str,
    ) -> rusqlite::Result<()> {
        self.conn.execute(
            "
            DELETE FROM trust_store
            WHERE deployment_id = ?1 AND instance_id = ?2 AND ip = ?3
            ",
            params![deployment_id, instance_id, ip],
        )?;
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
pub struct StoredSecretRef {
    pub name: String,
    pub secret_ref: String,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct NewControllerState<'a> {
    pub active_deployment_label: Option<&'a str>,
    pub active_instance_id: Option<&'a str>,
    pub active_server_ip: Option<&'a str>,
    pub active_tunnel_domain: Option<&'a str>,
    pub active_deployment_state_json: Option<&'a str>,
    pub deploy_phase: DeployPhase,
    pub app_readiness_phase: AppReadinessPhase,
    pub last_error_code: Option<&'a str>,
    pub last_error_message: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct StoredControllerState {
    pub active_deployment_label: Option<String>,
    pub active_instance_id: Option<String>,
    pub active_server_ip: Option<String>,
    pub active_tunnel_domain: Option<String>,
    pub active_deployment_state_json: Option<String>,
    pub deploy_phase: DeployPhase,
    pub app_readiness_phase: AppReadinessPhase,
    pub last_error_code: Option<String>,
    pub last_error_message: Option<String>,
    pub updated_at_unix: i64,
}

fn deploy_phase_storage_name(value: DeployPhase) -> &'static str {
    value.as_str_name()
}

fn app_readiness_phase_storage_name(value: AppReadinessPhase) -> &'static str {
    value.as_str_name()
}

fn parse_deploy_phase_storage_value(value: String) -> rusqlite::Result<DeployPhase> {
    match value.as_str() {
        "DEPLOYMENT_ABSENT" => Ok(DeployPhase::Unspecified),
        "FAILED" => Ok(DeployPhase::Failed),
        "COMPLETED" => Ok(DeployPhase::Completed),
        other => DeployPhase::from_str_name(other)
            .ok_or_else(|| invalid_controller_state_enum("deploy_phase", other)),
    }
}

fn parse_app_readiness_phase_storage_value(value: String) -> rusqlite::Result<AppReadinessPhase> {
    AppReadinessPhase::from_str_name(&value)
        .ok_or_else(|| invalid_controller_state_enum("app_readiness_phase", &value))
}

fn invalid_controller_state_enum(column: &str, value: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        Type::Text,
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid controller state {column}: {value}"),
        )),
    )
}

#[derive(Debug, Clone)]
pub struct StoredSelectorIntent {
    pub group_name: String,
    pub desired_route: String,
    pub updated_at_unix: i64,
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
        let latest_operation = state
            .latest_operation_by_kind("start_local_runtime")
            .unwrap()
            .unwrap();
        assert_eq!(latest_operation.id, operation.id);
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
        state
            .upsert_secret_ref("provider.vultr.api_key", "env:VULTR_API_KEY")
            .unwrap();
        let secret_ref = state
            .get_secret_ref("provider.vultr.api_key")
            .unwrap()
            .unwrap();
        assert_eq!(secret_ref.secret_ref, "env:VULTR_API_KEY");
        let controller_state = state
            .upsert_controller_state(NewControllerState {
                active_deployment_label: Some("deploy-1"),
                active_instance_id: Some("instance-1"),
                active_server_ip: Some("203.0.113.10"),
                active_tunnel_domain: Some("edge.alegria.by"),
                active_deployment_state_json: Some(
                    r#"{"label":"deploy-1","instance_id":"instance-1"}"#,
                ),
                deploy_phase: DeployPhase::AppReadyCompleted,
                app_readiness_phase: AppReadinessPhase::AppReady,
                last_error_code: None,
                last_error_message: None,
            })
            .unwrap();
        assert_eq!(
            controller_state.active_deployment_label.as_deref(),
            Some("deploy-1")
        );
        assert!(
            controller_state
                .active_deployment_state_json
                .as_deref()
                .is_some_and(|value| value.contains(r#""instance_id":"instance-1""#))
        );
        state
            .upsert_selector_intent("proxy-selector", "auto-direct-tunnel")
            .unwrap();
        state
            .upsert_selector_intent("wsl-selector", "auto-warp-tunnel")
            .unwrap();
        assert_eq!(state.list_selector_intents().unwrap().len(), 2);
        assert_eq!(state.list_secret_refs().unwrap().len(), 1);
        assert_eq!(state.list_trust_entries().unwrap().len(), 1);
        let deployment = state
            .record_deployment("deploy-1", "instance-1", "203.0.113.10")
            .unwrap();
        assert_eq!(deployment.server_ip, "203.0.113.10");
        let found_deployment = state
            .find_deployment_by_instance("instance-1")
            .unwrap()
            .unwrap();
        assert_eq!(found_deployment.deployment_label, "deploy-1");
        state.clear_deployment_by_label("deploy-1").unwrap();
        assert!(state.latest_deployment().unwrap().is_none());
        let deployment = state
            .record_deployment("deploy-1", "instance-1", "203.0.113.10")
            .unwrap();
        assert_eq!(deployment.server_ip, "203.0.113.10");
        assert_eq!(
            state.latest_deployment().unwrap().unwrap().instance_id,
            "instance-1"
        );
        state
            .clear_trust_entry("deploy-1", "instance-1", "203.0.113.10")
            .unwrap();
        assert!(state.list_trust_entries().unwrap().is_empty());
        state
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
        state.clear_deployment_by_instance("instance-1").unwrap();
        assert!(state.latest_deployment().unwrap().is_none());
        state
            .clear_trust_entries(Some("instance-1"), Some("203.0.113.10"))
            .unwrap();
        assert!(state.list_trust_entries().unwrap().is_empty());
        state.clear_controller_state().unwrap();
        assert_eq!(
            state
                .get_controller_state()
                .unwrap()
                .unwrap()
                .app_readiness_phase,
            AppReadinessPhase::DeploymentAbsent
        );
        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn drops_legacy_desired_state_table_during_migration() {
        let db_path = std::env::temp_dir().join(format!(
            "edge-state-migrate-{}.sqlite",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE desired_state (
                key TEXT PRIMARY KEY,
                value_blob BLOB NOT NULL,
                updated_at_unix INTEGER NOT NULL
            );
            INSERT INTO desired_state (key, value_blob, updated_at_unix)
            VALUES ('active_deployment_label', x'74657374', 1);
            ",
        )
        .unwrap();
        drop(conn);

        let state = EdgeState::open_or_create(&db_path).unwrap();
        let exists: i64 = state
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'desired_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 0);
        let _ = std::fs::remove_file(db_path);
    }
}
