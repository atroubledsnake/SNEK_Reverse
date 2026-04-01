fn main() {
    if let Err(e) = snek_reverse::snek_entry() {
        eprintln!("Failed to launch GUI: {:?}", e);
    }
}
