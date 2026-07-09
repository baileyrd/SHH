// Prevents an extra terminal window from popping up on Windows in release
// builds — irrelevant on Linux/macOS but harmless to always set.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod hosts;
mod identities;
mod sessions;

pub struct AppState {
    pub(crate) hosts: hosts::HostStore,
    pub(crate) sessions: sessions::SessionRegistry,
}

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            hosts: hosts::HostStore::load(),
            sessions: sessions::SessionRegistry::default(),
        })
        .invoke_handler(tauri::generate_handler![
            hosts::list_hosts,
            hosts::save_host,
            hosts::delete_host,
            identities::list_identities,
            identities::generate_identity,
            sessions::connect_host,
            sessions::send_input,
            sessions::resize_session,
            sessions::disconnect_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the SHH GUI");
}
