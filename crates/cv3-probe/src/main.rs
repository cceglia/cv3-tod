use std::process::ExitCode;

fn main() -> ExitCode {
    println!(
        "cvctl {} (cv3-core {})",
        env!("CARGO_PKG_VERSION"),
        cv3_core::VERSION
    );
    println!("not wired to the sensor yet; see docs/adr for the plan");
    ExitCode::SUCCESS
}
