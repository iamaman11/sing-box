use std::io::{self, Write};
use std::process::ExitCode;

use edge_shared_types::AgentState;

fn main() -> ExitCode {
    let state = AgentState::bootstrap_placeholder();
    match io::stdout().write_all(&state.encode_proto()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_placeholder_proto() {
        let bytes = AgentState::bootstrap_placeholder().encode_proto();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], 0x08);
    }
}
