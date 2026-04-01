pub mod analysis;
pub mod formats;
pub mod gui;
pub mod logging;
pub mod memory;
pub mod native;
pub mod threading;

pub fn snek_entry() -> Result<(), eframe::Error> {
    gui::run_gui()
}

