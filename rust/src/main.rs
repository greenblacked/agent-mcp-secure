use agent_mcp_secure::{exit_code, scan_tools, FailOn, Tool};
use std::env;
use std::fs;
use std::process;

const USAGE: &str = "Usage: agent-mcp-secure [--fail-on low|medium|high|none] <tools.json>

Exit codes: 0 no findings at or above --fail-on (default medium),
            1 findings, 2 usage or input error.";

/// Print an error and exit with the usage/input error code.
fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    process::exit(2);
}

fn parse_args() -> (String, FailOn) {
    let mut path = None;
    let mut fail_on = FailOn::Medium;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                process::exit(0);
            }
            "--fail-on" => {
                let value = args.next().unwrap_or_else(|| fail(USAGE));
                fail_on = value.parse().unwrap_or_else(|e: String| fail(&e));
            }
            _ if arg.starts_with("--fail-on=") => {
                fail_on = arg["--fail-on=".len()..]
                    .parse()
                    .unwrap_or_else(|e: String| fail(&e));
            }
            _ if arg.starts_with('-') => fail(&format!("unknown option {arg:?}\n\n{USAGE}")),
            _ if path.is_none() => path = Some(arg),
            _ => fail(USAGE),
        }
    }
    (path.unwrap_or_else(|| fail(USAGE)), fail_on)
}

fn main() {
    let (path, fail_on) = parse_args();

    let content =
        fs::read_to_string(&path).unwrap_or_else(|e| fail(&format!("Failed to read {path}: {e}")));

    let tools: Vec<Tool> = serde_json::from_str(&content)
        .unwrap_or_else(|e| fail(&format!("Invalid JSON in {path}: {e}")));

    let results = scan_tools(&tools);
    if results.is_empty() {
        println!("No high-signal findings.");
    } else {
        let json = serde_json::to_string_pretty(&results)
            .unwrap_or_else(|e| fail(&format!("Failed to serialize results: {e}")));
        println!("{json}");
    }
    process::exit(exit_code(&results, fail_on));
}
