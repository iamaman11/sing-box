use edge_shared_types::AgentState;

fn main() {
    let state = AgentState::bootstrap_placeholder();
    println!("{}", render_agent_state_json(&state));
}

fn render_agent_state_json(state: &AgentState) -> String {
    let active_bundle_id = match &state.active_bundle_id {
        Some(value) => format!("\"{}\"", escape_json(value)),
        None => "null".to_owned(),
    };
    let degraded_reasons = state
        .degraded_reasons
        .iter()
        .map(|reason| format!("\"{}\"", escape_json(reason)))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"healthy\":{},\"ready\":{},\"topology_version\":\"{}\",\"active_bundle_id\":{},\"degraded_reasons\":[{}]}}",
        state.healthy,
        state.ready,
        escape_json(&state.topology_version),
        active_bundle_id,
        degraded_reasons
    )
}

fn escape_json(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => escaped.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => escaped.push(ch),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_placeholder_json() {
        let json = render_agent_state_json(&AgentState::bootstrap_placeholder());
        assert!(json.contains("\"healthy\":true"));
        assert!(json.contains("\"ready\":false"));
        assert!(json.contains("runtime inspection not implemented in phase 0"));
    }

    #[test]
    fn escapes_json_strings() {
        assert_eq!(escape_json("a\"b\\c\n"), "a\\\"b\\\\c\\n");
    }
}
