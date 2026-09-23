//! Unit tests for src/ui.rs output gating.

use baco::ui::Ui;
use serial_test::serial;

#[test]
fn quiet_suppresses_lines() {
    assert!(!Ui::new(true).should_print());
}

#[test]
fn non_quiet_prints_lines() {
    assert!(Ui::new(false).should_print());
}

#[test]
#[serial]
fn no_color_env_disables_color() {
    let saved = std::env::var_os("NO_COLOR");
    unsafe { std::env::set_var("NO_COLOR", "1") };
    assert!(!baco::ui::use_color());
    unsafe { std::env::remove_var("NO_COLOR") };
    assert!(baco::ui::use_color());
    if let Some(v) = saved {
        unsafe { std::env::set_var("NO_COLOR", v) };
    }
}
