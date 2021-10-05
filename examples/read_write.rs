#[allow(dead_code, unused_imports)]
use nfc_nci::*;
use std::{error::Error, sync::mpsc};

fn main() -> Result<(), Box<dyn Error>> {
    const TAG_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let (tx, rx) = mpsc::channel();

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
    let ndef_info = tag.ndef_info()?;
    println!(
        "Has NDEF message with size: {} bytes",
        ndef_info.current_ndef_length
    );
    tag.format()?;
    let ndef_info = tag.ndef_info()?;
    println!(
        "Formatted. Now NDEF message has size: {} bytes",
        ndef_info.current_ndef_length
    );
    tag.write_ndef(NdefType::Text{
        language_code: "en".to_string(),
        text: "Hello world! Hello Rust!".to_string(),
    })?;
    let ndef_info = tag.ndef_info()?;
    println!(
        "Wrote \"Hello world! Hello Rust!\". Now NDEF message has size: {} bytes",
        ndef_info.current_ndef_length
    );

    let ndef = tag.read_ndef()?;
    if let NdefType::Text{text, language_code} = ndef {
        println!("Read text {} in {}", text, language_code);
    }

    Ok(())
}
