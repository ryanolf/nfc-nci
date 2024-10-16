use nfc_nci::*;
use std::{error::Error, sync::mpsc};

fn main() -> Result<(), Box<dyn Error>> {
    const TAG_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let (tx, rx) = mpsc::channel();

    let mut manager = NFCManager::new();
    manager.initialize()?;
    let tx2 = tx.clone();
    let arrival_callback = move |tag| {
        // How to handle failed send?
        println!("Tag arrived.");
        if tx2.send(tag).is_err() {
            println!("Error sending from callback")
        };
    };
    let departure_callback = move || {
        println!("Tag departed");
    };
    manager.register_tag_callbacks(Some(arrival_callback), Some(departure_callback));

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
    tag.write_ndef(
        [
            NdefRecord::Text {
                language_code: "en".to_string(),
                text: "Hello world!".to_string(),
            },
            NdefRecord::Text {
                language_code: "en".to_string(),
                text: "Hello rust!".to_string(),
            },
        ][..]
            .into(),
    )?;
    let ndef_info = tag.ndef_info()?;
    println!(
        "Wrote tag. Now NDEF message has size: {} bytes",
        ndef_info.current_ndef_length
    );

    let mut ndef_iter = tag.read_ndef()?.into_iter();
    while let Some(NdefRecord::Text {
        text,
        language_code,
    }) = ndef_iter.next()
    {
        println!("Read text record in {}: {}", language_code, text);
    }

    Ok(())
}
