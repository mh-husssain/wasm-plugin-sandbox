use clap::{Parser, Subcommand};
use malware_cli::{execute_run, execute_validate_package, format_run_output, RunCommand};
use malware_core::AnalysisService;
use malware_plugin_runtime::{PackageValidationReport, WasmPluginRuntime};
use std::sync::Arc;

/// CLI root options.
#[derive(Debug, Parser)]
#[command(name = "malware-cli", about = "Malware analysis CLI")]
struct Cli {
    /// Selected subcommand.
    #[command(subcommand)]
    command: Commands,
}

/// Supported CLI subcommands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Run malware analysis using a selected plugin.
    Run {
        /// Plugin package name.
        #[arg(long)]
        plugin: String,
        /// Sample path or identifier.
        #[arg(long)]
        sample: String,
    },
    /// Validate plugin package contracts without execution.
    ValidatePackage {
        /// Plugin package name.
        #[arg(long)]
        plugin: String,
    },
}

/// Asynchronous binary entrypoint.
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let runtime = Arc::new(WasmPluginRuntime::new());
    let service = AnalysisService::new(runtime.clone());

    match cli.command {
        Commands::Run { plugin, sample } => {
            let command = RunCommand { plugin, sample };

            match execute_run(&service, command) {
                Ok(result) => {
                    println!("{}", format_run_output(&result));
                }
                Err(error) => {
                    eprintln!("analysis failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        Commands::ValidatePackage { plugin } => match execute_validate_package(&runtime, &plugin) {
            Ok(report) => match serde_json::to_string_pretty(&report) {
                Ok(output) => println!("{output}"),
                Err(error) => {
                    eprintln!("failed to render validation report: {error}");
                    std::process::exit(1);
                }
            },
            Err(error) => {
                let report = PackageValidationReport::from_error(&plugin, &error);
                match serde_json::to_string_pretty(&report) {
                    Ok(output) => eprintln!("{output}"),
                    Err(render_error) => {
                        eprintln!("package validation failed: {error}");
                        eprintln!("failed to render validation report: {render_error}");
                    }
                }
                std::process::exit(1);
            }
        },
    }
}
