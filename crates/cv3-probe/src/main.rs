use std::io::{self, Write};
use std::process::ExitCode;

use cv3_probe::cli;
use cv3_probe::nusb_backend::NusbBackend;
use cv3_probe::signals::SignalWatch;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Install the handlers before anything touches the sensor, so an interrupt during discovery
    // unwinds through the probe's guard rather than killing the process with the claim held.
    let shutdown = match SignalWatch::install() {
        Ok(watch) => watch,
        Err(error) => {
            eprintln!("cvctl: installing signal handlers failed: {error}");
            return ExitCode::from(cli::EXIT_OTHER);
        }
    };

    let mut backend = NusbBackend::new();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();

    let code = cli::run(&args, &mut backend, &shutdown, &mut out, &mut err);
    let _ = out.flush();
    let _ = err.flush();

    ExitCode::from(code)
}
