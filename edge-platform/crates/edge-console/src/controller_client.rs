use super::*;

pub(super) async fn connect_controller(
    endpoint: String,
) -> Result<ControllerServiceClient<Channel>, Box<dyn std::error::Error>> {
    match ControllerServiceClient::<Channel>::connect(endpoint.clone()).await {
        Ok(client) => Ok(client),
        Err(first_err) => {
            ensure_controller_running(&endpoint)?;
            let mut last_error = None;
            for _ in 0..20 {
                match ControllerServiceClient::<Channel>::connect(endpoint.clone()).await {
                    Ok(client) => return Ok(client),
                    Err(err) => {
                        last_error = Some(err);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            }
            let second_err = last_error
                .map(|err| err.to_string())
                .unwrap_or_else(|| "unknown error".to_owned());
            Err(format!(
                "failed to connect to SCM-owned controller: first={first_err}; second={second_err}"
            )
            .into())
        }
    }
}

pub(super) async fn fetch_status(
    endpoint: String,
) -> Result<ControllerStatus, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client.get_status(Request::new(Empty {})).await?;
    Ok(response.into_inner())
}

pub(super) async fn fetch_credential_state(
    endpoint: String,
) -> Result<Option<edge_shared_types::LocalCredentialState>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    Ok(client
        .get_credential_state(Request::new(Empty {}))
        .await?
        .into_inner()
        .state)
}

pub(super) async fn fetch_doctor(
    endpoint: String,
) -> Result<DoctorResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .doctor(Request::new(DoctorRequest {
            require_server_ready: true,
            require_local_runtime: true,
            require_egress_traces: true,
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn list_secret_refs(
    endpoint: String,
) -> Result<Vec<SecretRefEntry>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .list_secret_refs(Request::new(ListSecretRefsRequest {}))
        .await?;
    Ok(response.into_inner().secrets)
}

pub(super) async fn get_secret_ref(
    endpoint: String,
    name: &str,
) -> Result<SecretRefEntry, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_secret_ref(Request::new(GetSecretRefRequest {
            name: name.to_owned(),
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn set_secret_ref(
    endpoint: String,
    name: &str,
    secret_ref: &str,
) -> Result<SecretRefEntry, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .set_secret_ref(Request::new(SetSecretRefRequest {
            name: name.to_owned(),
            secret_ref: secret_ref.to_owned(),
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn start_local(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .start_local_runtime(Request::new(StartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            force_restart: false,
            visible_window: false,
            native_system_effect: Vec::new(),
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn start_local_visible(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .start_local_runtime(Request::new(StartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            force_restart: false,
            visible_window: true,
            native_system_effect: Vec::new(),
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn stop_local(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .stop_local_runtime(Request::new(StopLocalRuntimeRequest {
            config_path: None,
            expected_config_only: true,
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn restart_local(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .restart_local_runtime(Request::new(RestartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            visible_window: false,
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn restart_local_visible(
    endpoint: String,
) -> Result<LocalRuntimeResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .restart_local_runtime(Request::new(RestartLocalRuntimeRequest {
            singbox_binary_path: None,
            config_path: None,
            state_path: None,
            visible_window: true,
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn fetch_selector_state(
    endpoint: String,
    group: &str,
) -> Result<SelectorState, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_selector_state(Request::new(GetSelectorStateRequest {
            group: Some(group.to_owned()),
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn set_selector(
    endpoint: String,
    group: &str,
    name: &str,
) -> Result<SetSelectorResponse, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .set_selector(Request::new(SetSelectorRequest {
            group: group.to_owned(),
            name: name.to_owned(),
        }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn fetch_trace(
    endpoint: String,
) -> Result<TraceObservation, Box<dyn std::error::Error>> {
    fetch_trace_with_proxy(endpoint, None).await
}

pub(super) async fn fetch_trace_with_proxy(
    endpoint: String,
    proxy_url: Option<String>,
) -> Result<TraceObservation, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_trace(Request::new(GetTraceRequest { proxy_url }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn get_operation(
    endpoint: String,
    operation_id: i64,
) -> Result<OperationStatus, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .get_operation(Request::new(GetOperationRequest { operation_id }))
        .await?;
    Ok(response.into_inner())
}

pub(super) async fn list_operation_events(
    endpoint: String,
    operation_id: i64,
) -> Result<Vec<edge_shared_types::OperationEvent>, Box<dyn std::error::Error>> {
    let mut client = connect_controller(endpoint).await?;
    let response = client
        .list_operation_events(Request::new(ListOperationEventsRequest { operation_id }))
        .await?;
    Ok(response.into_inner().events)
}

pub(super) async fn watch_operation(
    endpoint: String,
    operation_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut last_event_id = 0_i64;
    loop {
        let status = get_operation(endpoint.clone(), operation_id).await?;
        print_operation_summary(&status);

        let events = list_operation_events(endpoint.clone(), operation_id).await?;
        for event in events {
            if event.id <= last_event_id {
                continue;
            }
            println!("[{}] {}", event.id, event.message);
            last_event_id = event.id;
        }

        let current = status
            .operation
            .as_ref()
            .map(|operation| operation.status)
            .unwrap_or_default();
        if current == edge_shared_types::OperationLifecycleStatus::Succeeded as i32
            || current == edge_shared_types::OperationLifecycleStatus::Failed as i32
        {
            return Ok(());
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}
