use super::PresetCommands;
use crate::preset;

pub fn run_preset_command(action: PresetCommands, quiet: bool) {
    let ui = crate::ui::Ui::new(quiet);
    match action {
        PresetCommands::List { verbose } => {
            let presets = preset::list_available_presets();
            if presets.is_empty() {
                ui.line("No presets available.");
                return;
            }

            if verbose {
                for name in &presets {
                    // Extract preset name (strip " (user)" suffix if present)
                    let preset_name = name.split(" (").next().unwrap_or(name.as_str());
                    ui.emit(format!("\n=== {} ===", name));
                    match preset::load_preset(preset_name) {
                        Ok(_) => {
                            // For verbose mode, we'd need to read the raw TOML
                            // For now, just show the name
                            ui.emit(format!("Preset: {}", preset_name));
                        }
                        Err(e) => {
                            ui.emit(format!("Error loading preset: {}", e));
                        }
                    }
                }
            } else {
                ui.emit("Available presets:");
                for name in presets {
                    ui.emit(format!("  - {}", name));
                }
            }
        }
        PresetCommands::Show { name } => {
            // Load preset to verify it exists
            match preset::load_preset(&name) {
                Ok(_) => {
                    // For show, we need to read the raw TOML content
                    // Try bundled first (single source of truth - has all 8 presets)
                    if let Some(content) = preset::get_bundled_preset_for_display(&name) {
                        ui.emit(content);
                    } else {
                        // Try user directory
                        let user_path = preset::user_preset_path(&name);
                        if user_path.exists() {
                            match std::fs::read_to_string(&user_path) {
                                Ok(content) => ui.emit(&content),
                                Err(e) => {
                                    ui.error(format!("Failed to read preset: {}", e));
                                    std::process::exit(1);
                                }
                            }
                        } else {
                            ui.error(format!("Preset '{}' not found", name));
                            std::process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    ui.error(format!("{e}"));
                    std::process::exit(1);
                }
            }
        }
    }
}
