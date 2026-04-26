use edge_shared_types::TraceObservation;
use reqwest::{Client, Proxy};

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
            return TraceObservation::unavailable(format!("trace request failed: {err}"));
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
