use clap::Subcommand;

#[derive(Subcommand)]
pub enum PresetCommands {
    List {
        #[arg(long, help = "Show full TOML for each preset")]
        verbose: bool,
    },
    Show {
        #[arg(help = "Preset name to display")]
        name: String,
    },
}

pub mod doctor;
pub mod eval;
pub mod preset;
pub mod report;
pub mod scan;
pub mod verify;
