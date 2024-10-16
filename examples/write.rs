use nfc_nci::*;
use std::env;
use std::{error::Error, sync::mpsc};

fn main() -> Result<(), Box<dyn Error>> {
    const TAG_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let (tx, rx) = mpsc::channel();

    let mut manager = NFCManager::new();
    if let Err(e) = manager.initialize() {
        println!("Error initializing NFC: {}", e);
        return Err(Box::new(e));
    }
    manager.register_tag_callbacks(
        Some(move |tag_info| {
            // How to handle failed send?
            if tx.send(tag_info).is_err() {
                println!("Error sending from callback")
            }
        }),
        None::<fn()>,
    );
    manager.enable_discovery(None, Some(true), None, None);

    // Wait for tag
    println!("Waiting for tag...");
    let tag = match rx.recv_timeout(TAG_READ_TIMEOUT) {
        Ok(tag) => tag,
        Err(_) => return Err("Timedout waiting for tag. Is there a tag near the reader?".into()),
    };
    println!("Got tag with UID: {:x?}", tag.uid);

    tag.format()?;

    let mut msg = NdefMessage::default();

    for cmd in env::args().skip(1) {
        println!("Preparing record with: {}", cmd);
        msg.records.push(NdefRecord::Text {
            language_code: "en".to_string(),
            text: cmd,
        })
    }

    // No args
    if msg.records.is_empty() {
        return Err("No command to write?".into());
    }

    tag.write_ndef(msg)?;
    let mut ndef = tag.read_ndef()?.into_iter();
    while let Some(NdefRecord::Text {
        text,
        language_code: _,
    }) = ndef.next()
    {
        println!("Tag written with: \"{}\"", text);
    }

    Ok(())
}
