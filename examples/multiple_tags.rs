use nfc_nci::*;
use std::{error::Error, sync::mpsc};

fn main() -> Result<(), Box<dyn Error>> {
    const TAG_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let (tx, rx) = mpsc::channel();

    let mut manager = NFCManager::initialize()?;
    let tx2 = tx.clone();
    let arrival_callback = move |tag| {
        // How to handle failed send?
        // println!("Tag arrived.");
        if tx2.send(tag).is_err() {
            println!("Error sending from callback")
        };
    };
    // let departure_callback = move || {
    //     println!("Tag departed");
    // };
    manager.register_tag_callbacks(Some(arrival_callback), Option::<fn()>::None);

    manager.enable_discovery(None, Some(true), None, None);

    // Wait for tag(s)
    let mut num_tags = 0;
    let mut tag_number = 1;
    loop {
        if let Ok(tag) = rx.recv_timeout(TAG_READ_TIMEOUT) {
            if tag_number == 1 {
                num_tags = manager.get_num_tags();
                println!("There are {} tags found", num_tags);
            }
            let ndef_info = tag.ndef_info()?;
            println!(
                "Got tag with UID {:x?} and size {} bytes",
                tag.uid(),
                ndef_info.current_ndef_length()
            );
            if tag_number < num_tags {
                manager.get_next_tag()?;
                tag_number += 1;
            } else {
                break;
            }
        }
    }

    Ok(())
}
