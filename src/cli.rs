use std::{env, path::PathBuf, process::ExitCode};

use crate::{
    errors::{ClassifiedError, ErrorCode},
    infra::{CatalogAdapter, CveAdapter, DriverAdapter, WinbindexAdapter},
    model::driver::DriverOutcome,
    service::{DownloadRequest, DownloadService, InfoService, ServiceError},
};

const USAGE: &str = "Usage:
  fastoneday info <CVE>
  fastoneday download <CVE> <PRODUCT> <OUTPUT>

Options:
  --driver <DRIVER>
  --before-kb <KB>
  --before-sha256 <SHA256>
  --after-sha256 <SHA256>";

pub fn run() -> ExitCode {
    match parse(env::args().skip(1)) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("fastoneday {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Ok(Command::Info { cve_code, driver }) => run_info(&cve_code, driver.as_deref()),
        Ok(Command::Download(request)) => run_download(&request),
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

enum Command {
    Help,
    Version,
    Info {
        cve_code: String,
        driver: Option<String>,
    },
    Download(DownloadRequest),
}

#[derive(Default)]
struct Options {
    driver: Option<String>,
    before_kb: Option<String>,
    before_sha256: Option<String>,
    after_sha256: Option<String>,
}

fn parse(arguments: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let Some(command) = arguments.next() else {
        return Ok(Command::Help);
    };
    if matches!(command.as_str(), "help" | "-h" | "--help") {
        return Ok(Command::Help);
    }
    if matches!(command.as_str(), "-V" | "--version") {
        return Ok(Command::Version);
    }

    let (positionals, options) = parse_values(arguments)?;
    match command.as_str() {
        "info"
            if positionals.len() == 1
                && options.before_kb.is_none()
                && options.before_sha256.is_none()
                && options.after_sha256.is_none() =>
        {
            Ok(Command::Info {
                cve_code: positionals[0].clone(),
                driver: options.driver,
            })
        }
        "info" => Err("info requires exactly one CVE".into()),
        "download" if positionals.len() == 3 => Ok(Command::Download(DownloadRequest {
            cve_code: positionals[0].clone(),
            product: positionals[1].clone(),
            output_directory: PathBuf::from(&positionals[2]),
            driver_override: options.driver,
            before_kb: options.before_kb,
            before_sha256: options.before_sha256,
            after_sha256: options.after_sha256,
        })),
        "download" => Err("download requires CVE, PRODUCT, and OUTPUT".into()),
        _ => Err(format!("unknown command `{command}`")),
    }
}

fn parse_values(
    arguments: impl IntoIterator<Item = String>,
) -> Result<(Vec<String>, Options), String> {
    let mut values = arguments.into_iter();
    let mut positionals = Vec::new();
    let mut options = Options::default();

    while let Some(value) = values.next() {
        let target = match value.as_str() {
            "--driver" => &mut options.driver,
            "--before-kb" => &mut options.before_kb,
            "--before-sha256" => &mut options.before_sha256,
            "--after-sha256" => &mut options.after_sha256,
            unknown if unknown.starts_with('-') => {
                return Err(format!("unknown option `{unknown}`"));
            }
            _ => {
                positionals.push(value);
                continue;
            }
        };

        if target.is_some() {
            return Err(format!("option `{value}` was provided more than once"));
        }
        *target = Some(
            values
                .next()
                .ok_or_else(|| format!("option `{value}` requires a value"))?,
        );
    }

    Ok((positionals, options))
}

fn run_info(cve_code: &str, driver_override: Option<&str>) -> ExitCode {
    let cve = CveAdapter::default();
    let driver = DriverAdapter;
    match InfoService::new(&cve, &driver).get(cve_code, driver_override) {
        Ok(info) => {
            let metadata = &info.cve.normalized;
            println!("{}: {}", metadata.cve_code, metadata.title);
            match &info.driver.outcome {
                DriverOutcome::Confirmed { driver } => println!("driver: {}", driver.name),
                DriverOutcome::Probable { driver } => {
                    println!("driver: {} (needs --driver confirmation)", driver.name)
                }
                DriverOutcome::Conflict { drivers } => println!(
                    "driver candidates: {}",
                    drivers
                        .iter()
                        .map(|candidate| candidate.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                DriverOutcome::Unresolved { .. } => println!("driver: unresolved"),
            }
            println!("products:");
            for patch in &metadata.catalog {
                let before = if patch.before_kb.candidates().is_empty() {
                    "?".into()
                } else {
                    patch.before_kb.candidates().join("/")
                };
                println!("  {}: {} -> {}", patch.os_version, before, patch.after_kb);
            }
            ExitCode::SUCCESS
        }
        Err(error) => print_service_error(&error),
    }
}

fn run_download(request: &DownloadRequest) -> ExitCode {
    let cve = CveAdapter::default();
    let driver = DriverAdapter;
    let winbindex = WinbindexAdapter::default();
    let catalog = CatalogAdapter::default().with_progress();
    let service = DownloadService::new(&cve, &driver, &winbindex, &catalog);

    match service.download(request) {
        Ok(result) => {
            println!("{} / {}", result.cve_code, result.driver_name);
            println!(
                "before {}: {} ({})",
                result.before_kb,
                result.before.destination.display(),
                result.before.sha256
            );
            println!(
                "after  {}: {} ({})",
                result.after_kb,
                result.after.destination.display(),
                result.after.sha256
            );
            ExitCode::SUCCESS
        }
        Err(error) => print_service_error(&error),
    }
}

fn print_service_error(error: &ServiceError) -> ExitCode {
    eprintln!("error [{:?}]: {error}", error.code());
    if error.retryable() {
        eprintln!("retryable: yes");
    }
    match error.code() {
        ErrorCode::AmbiguousSelection => ExitCode::from(2),
        _ => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_short_info_command() {
        let command = parse(["info".into(), "CVE-2026-1234".into()]).unwrap();
        assert!(matches!(command, Command::Info { driver: None, .. }));
    }

    #[test]
    fn parses_download_options_without_a_cli_framework() {
        let command = parse([
            "download".into(),
            "CVE-2026-1234".into(),
            "Windows 11 x64".into(),
            "out".into(),
            "--driver".into(),
            "clfs.sys".into(),
        ])
        .unwrap();

        let Command::Download(request) = command else {
            panic!("expected download command");
        };
        assert_eq!(request.driver_override.as_deref(), Some("clfs.sys"));
    }
}
