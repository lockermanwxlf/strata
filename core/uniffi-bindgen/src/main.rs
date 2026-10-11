//! Project-local copy of the UniFFI binding generator, so the generator version
//! always matches the `uniffi` version the core is built with.
fn main() {
    uniffi::uniffi_bindgen_main()
}
