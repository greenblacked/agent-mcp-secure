use agent_mcp_secure::{scan_tools, Tool};
use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: agent-mcp-secure <tools.json>");
        process::exit(1);
    }

    let content = fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("Failed to read file: {}", e);
        process::exit(1);
    });

    let tools: Vec<Tool> = serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Invalid JSON: {}", e);
        process::exit(1);
    });

    let results = scan_tools(&tools);
    if results.is_empty() {
        println!("No high-signal findings.");
    } else {
        println!("{}", serde_json::to_string_pretty(&results).unwrap());
    }
}
