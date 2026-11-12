use std::{path::PathBuf, process::ExitCode};

use fastoneday::{app::Services, config::Settings, headless, tui};

const HELP: &str = "\
fastoneday — fetch exact pre/post-patch Microsoft binaries for a CVE

USAGE
  fastoneday [CVE]                 interactive terminal UI (default)
  fastoneday fetch CVE [OPTIONS]   non-interactive, for scripts

FETCH OPTIONS
  -b, --binary NAME    binary to fetch (default: best detected candidate)
  -p, --product N      product row from the list (default: 1, the recommended one)
  -l, --list           only print products and binary candidates

GLOBAL OPTIONS
  -w, --workspace DIR  where cases and the cache live
                       (default: $FASTONEDAY_HOME or ./fastoneday-workspace)
      --no-pdb         do not download PDBs
  -h, --help           show this help
  -V, --version        show the version
";

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let mut settings = Settings::from_env();
    let mut positional = Vec::new();
    let mut binary = None;
    let mut product = None;
    let mut list_only = false;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        let mut value = |name: &str| iter.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(());
            }
            "-V" | "--version" => {
                println!("fastoneday {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "-w" | "--workspace" => settings = settings.with_workspace(PathBuf::from(value(&arg)?)),
            "-b" | "--binary" => binary = Some(value(&arg)?),
            "-p" | "--product" => {
                let raw = value(&arg)?;
                product = Some(
                    raw.parse::<usize>()
                        .map_err(|_| format!("--product expects a number, got `{raw}`"))?,
                );
            }
            "-l" | "--list" => list_only = true,
            "--no-pdb" => settings.fetch_pdbs = false,
            other if other.starts_with('-') => {
                return Err(format!("unknown option `{other}` (see --help)"));
            }
            _ => positional.push(arg),
        }
    }

    let services = Services::new(settings);
    match positional.first().map(String::as_str) {
        Some("fetch") => {
            let cve = positional.get(1).cloned().ok_or("fetch needs a CVE id")?;
            headless::run(
                services,
                headless::FetchArgs {
                    cve,
                    binary,
                    product,
                    list_only,
                },
            )
            .map_err(|e| e.to_string())
        }
        Some(cve) => tui::run(services, Some(cve.to_owned())).map_err(|e| e.to_string()),
        None => tui::run(services, None).map_err(|e| e.to_string()),
    }
}
