use nfc_nci::*;
use std::env;
use std::{error::Error, sync::mpsc};

fn main() -> Result<(), Box<dyn Error>> {
    const TAG_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let (tx, rx) = mpsc::channel();

    let msg: String;
    if let Some(input) = env::args().nth(1) {
        msg = input;
    } else {
        msg = "command:shuffle:on|;apple:album:1025210938".into();
    }

    let mut manager = NFCManager::new();
    manager.initialize()?;
    manager.register_tag_callbacks(Some(move |tag_info| {
        // How to handle failed send?
        match tx.send(tag_info) {
            Err(_) => println!("Error sending from callback"),
            _ => (),
        }
    }));
    manager.enable_discovery(None, Some(true), None, None);

    // Wait for tag
    let tag = match rx.recv_timeout(TAG_READ_TIMEOUT) {
        Ok(tag) => tag,
        Err(_) => return Err("Timedout waiting for tag. Is there a tag near the reader?".into()),
    };
    println!("Got tag with UID: {:x?}", tag.uid);

    tag.format()?;
    tag.write_ndef(NdefType::Text{
        language_code: "en".to_string(),
        text: msg,
    })?;
    let ndef = tag.read_ndef()?;
    if let NdefType::Text{text, language_code: _} = ndef {
        println!("Tag written with: \"{}\"", text);
    }

    Ok(())
}
