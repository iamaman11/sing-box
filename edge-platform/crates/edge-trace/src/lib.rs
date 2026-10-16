use edge_shared_types::TraceObservation;
use reqwest::{Client, Proxy, Url};
use std::error::Error as _;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Inspect only the exact local listener after a failed proxied HTTPS request.
/// This makes no upstream HTTP request, does not retry the failed request,
/// and does not mutate route selectors or credential state.
fn local_proxy_tcp_evidence(proxy_url: &str) -> &'static str {
    let Ok(url) = Url::parse(proxy_url) else {
        return "INVALID_PROXY_URL";
    };
    if url.scheme() != "http" || url.host_str() != Some("127.0.0.1") {
        return "NOT_LOCAL_HTTP_PROXY";
    }
    let Some(port) = url.port_or_known_default() else {
        return "INVALID_PROXY_PORT";
    };
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    match TcpStream::connect_timeout(&address, Duration::from_millis(500)) {
        Ok(_) => "ACCEPTING",
        Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => "REFUSED",
        Err(err) if err.kind() == std::io::ErrorKind::TimedOut => "TIMEOUT",
        Err(_) => "UNAVAILABLE",
    }
}

/// A bounded, privacy-preserving failure taxonomy for the existing proxy
/// transport. No URL, proxy credentials, headers, response body or raw
/// hyper/rustls error chain is emitted into GitHub workflow logs.
fn trace_transport_failure(err: &reqwest::Error, proxy_url: &str) -> String {
    let request_class = if err.is_timeout() {
        "TIMEOUT"
    } else if err.is_connect() {
        "CONNECT_OR_TLS"
    } else if err.is_request() {
        "REQUEST"
    } else if err.is_body() {
        "BODY"
    } else {
        "OTHER_TRANSPORT"
    };
    let mut io_kind = "NOT_OBSERVED".to_owned();
    let mut source = err.source();
    for _ in 0..8 {
        let Some(current) = source else { break };
        if let Some(io) = current.downcast_ref::<std::io::Error>() {
            io_kind = format!("{:?}", io.kind());
            break;
        }
        source = current.source();
    }
    format!(
        "trace request failed: phase=HTTPS_VIA_PROXY;request_class={request_class};io_kind={io_kind};local_proxy_tcp={}",
        local_proxy_tcp_evidence(proxy_url)
    )
}


pub async fn trace_via_proxy(proxy_url: &str) -> TraceObservation {
    let client = match Client::builder()
        .proxy(match Proxy::all(proxy_url) {
            Ok(proxy) => proxy,
            Err(err) => {
                return TraceObservation::unavailable(format!("invalid proxy URL: {err}"));
            }
        })
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return TraceObservation::unavailable(format!("failed to build trace client: {err}"));
        }
    };

    let response = match client
        .get("https://cloudflare.com/cdn-cgi/trace")
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            return TraceObservation::unavailable(trace_transport_failure(&err, proxy_url));
        }
    };

    let body = match response.error_for_status() {
        Ok(response) => match response.text().await {
            Ok(text) => text,
            Err(err) => {
                return TraceObservation::unavailable(format!(
                    "trace response body could not be read: {err}"
                ));
            }
        },
        Err(err) => {
            return TraceObservation::unavailable(format!("trace response failed: {err}"));
        }
    };

    parse_trace_body(&body)
}

fn parse_trace_body(body: &str) -> TraceObservation {
    let mut ip = None;
    let mut warp = None;
    let mut colo = None;

    for line in body.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "ip" => ip = Some(value.to_owned()),
                "warp" => warp = Some(value.to_owned()),
                "colo" => colo = Some(value.to_owned()),
                _ => {}
            }
        }
    }

    if ip.is_none() {
        return TraceObservation::unavailable("trace response did not contain ip");
    }

    TraceObservation {
        available: true,
        ip,
        warp,
        colo,
        note: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_listener_is_observed_without_http_or_credentials() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(
            local_proxy_tcp_evidence(&format!("http://127.0.0.1:{}", addr.port())),
            "ACCEPTING"
        );
    }

    #[test]
    fn nonlocal_or_invalid_proxies_are_not_probed() {
        assert_eq!(
            local_proxy_tcp_evidence("http://remote.invalid:443"),
            "NOT_LOCAL_HTTP_PROXY"
        );
        assert_eq!(
            local_proxy_tcp_evidence("not-a-url"),
            "INVALID_PROXY_URL"
        );
        assert_eq!(
            local_proxy_tcp_evidence("https://127.0.0.1:443"),
            "NOT_LOCAL_HTTP_PROXY"
        );
    }

    #[tokio::test]
    async fn failed_https_proxy_request_has_bounded_stage_and_no_sensitive_url() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let proxy = format!("http://127.0.0.1:{port}");
        let observation = trace_via_proxy(&proxy).await;
        assert!(!observation.available);
        let note = observation.note.unwrap();
        assert!(note.starts_with("trace request failed: phase=HTTPS_VIA_PROXY;"), "{note}");
        assert!(note.contains("request_class=CONNECT_OR_TLS"), "{note}");
        assert!(note.contains("local_proxy_tcp=REFUSED"), "{note}");
        assert!(!note.contains("cloudflare.com"), "{note}");
        assert!(!note.contains("127.0.0.1"), "{note}");
    }

    #[test]
    fn parses_cloudflare_trace_response() {
        let observation = parse_trace_body("ip=1.2.3.4\nwarp=on\ncolo=WAW\n");
        assert!(observation.available);
        assert_eq!(observation.ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(observation.warp.as_deref(), Some("on"));
        assert_eq!(observation.colo.as_deref(), Some("WAW"));
    }

    #[test]
    fn rejects_trace_without_ip() {
        let observation = parse_trace_body("warp=off\ncolo=MSQ\n");
        assert!(!observation.available);
        assert!(
            observation
                .note
                .as_deref()
                .unwrap_or_default()
                .contains("did not contain ip")
        );
    }
}
