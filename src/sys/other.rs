use crate::kill::KillError;
use crate::model::{Entry, Ident};
use std::io;

pub fn list_listeners() -> io::Result<Vec<Entry>> {
    Ok(Vec::new())
}

pub fn proc_start_token(_pid: i32) -> Result<u64, KillError> {
    Err(KillError::System("unsupported platform".to_string()))
}

pub fn kill_process(_id: Ident) -> Result<(), KillError> {
    Err(KillError::System("unsupported platform".to_string()))
}
