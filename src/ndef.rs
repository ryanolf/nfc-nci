use bitflags::bitflags;
use std::slice::Iter;

use crate::{
    NFCError::{self, NdefError, NdefRecordInvalid},
    Result,
};

const RTD_TEXT_FLAG_UTF16: u8 = 0x80;
const RTD_TEXT_LC_LENGTH_MASK: u8 = 63;
const RTD_TEXT: u8 = 0x54;
const RTD_URL: u8 = 0x55;
const TNF_WELLKNOWN: u8 = 0x01;

bitflags! {
    #[derive(Default)]
    struct NdefRecordFlags: u8 {
        const MESSAGE_BEGIN = 0x80;
        const MESSAGE_END = 0x40;
        const CHUNKED = 0x20;
        const SHORT = 0x10;
        const ID = 0x08;
        const TNF_BITS = 0x07;
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum NdefRecord {
    /// NDEF text: NFC Forum well-known type + RTD: 0x54
    Text { language_code: String, text: String },
    /// NDEF URL: NFC Forum well-known type + RTD: 0x55
    Url(String),
}

#[derive(Default, Debug, PartialEq)]
pub struct NdefMessage {
    pub records: Vec<NdefRecord>,
}

impl NdefRecord {
    fn payload(&self) -> Result<Vec<u8>> {
        let mut payload: Vec<u8>;
        match self {
            NdefRecord::Text {
                language_code,
                text,
            } => {
                if language_code.len() > 63 {
                    return Err(NdefError("Language code too long".into()));
                }
                if text.len() > u32::MAX as usize {
                    return Err(NdefError("Text length is too long".into()));
                }
                payload = Vec::with_capacity(1 + language_code.len() + text.len());
                // Push flags byte
                payload.push(language_code.len() as u8);
                // Push language code and text as bytes
                payload.extend_from_slice(language_code.as_bytes());
                payload.extend_from_slice(text.as_bytes());
            }
            NdefRecord::Url(_) => todo!(),
        }
        Ok(payload)
    }

    fn payload_type(&self) -> Vec<u8> {
        match self {
            NdefRecord::Text {
                language_code: _,
                text: _,
            } => vec![RTD_TEXT],
            NdefRecord::Url(_) => vec![RTD_URL],
        }
    }

    fn tnf(&self) -> NdefRecordFlags {
        NdefRecordFlags::from_bits_truncate(TNF_WELLKNOWN)
    }

    /// Do not support ID fields, chunking.
    pub fn content(&self, first: bool, last: bool) -> Result<Vec<u8>> {
        let mut content: Vec<u8>;

        let payload = self.payload()?;
        let payload_type = self.payload_type();
        let mut flags = self.tnf();
        if first {
            flags |= NdefRecordFlags::MESSAGE_BEGIN
        };
        if last {
            flags |= NdefRecordFlags::MESSAGE_END
        };
        if payload.len() < 256 {
            flags |= NdefRecordFlags::SHORT;
            content = Vec::with_capacity(3 + payload_type.len() + payload.len());
        } else {
            content = Vec::with_capacity(6 + payload_type.len() + payload.len());
        }

        content.push(flags.bits());
        content.push(payload_type.len() as u8);
        if payload.len() < 256 {
            content.push(payload.len() as u8);
        } else {
            content.extend((payload.len() as u32).to_be_bytes());
        }
        content.extend(payload_type);
        content.extend(payload);

        Ok(content)
    }

    #[cfg(test)]
    fn content_native(&self) -> Result<Vec<std::os::raw::c_uchar>> {
        use nfc_nci_sys as raw;
        use std::ffi::CString;

        let mut content: Vec<std::os::raw::c_uchar>;
        let content_len;
        match self {
            NdefRecord::Text {
                language_code,
                text,
            } => {
                // Allocate space in a vector for the NDEF.
                content = Vec::with_capacity(text.len() + 10);

                let language_code_ptr = CString::new(language_code.as_str())
                    .or(Err(NdefError("Invalid language code".into())))?
                    .into_raw();
                let text_content_ptr = CString::new(text.as_str())
                    .or(Err(NdefError("Invalid text".into())))?
                    .into_raw();
                content_len = unsafe {
                    raw::ndef_createText(
                        language_code_ptr,
                        text_content_ptr,
                        content.as_mut_ptr(),
                        content.capacity().try_into().unwrap(),
                    )
                };
                // Make sure raw pointer memory is freed, per into_raw() docs
                let (_, _) = unsafe {
                    (
                        CString::from_raw(language_code_ptr),
                        CString::from_raw(text_content_ptr),
                    )
                };
            }
            _ => todo!(),
        }

        if content_len <= 0 {
            Err(NdefError("Failed to encode NDEF text.".into()))
        } else {
            unsafe { content.set_len(content_len.try_into().unwrap()) };
            Ok(content)
        }
    }
}

impl TryFrom<&mut Iter<'_, u8>> for NdefRecord {
    type Error = NFCError;

    fn try_from(iter: &mut Iter<'_, u8>) -> Result<Self> {
        let flags = NdefRecordFlags::from_bits_truncate(*iter.next().ok_or(NdefRecordInvalid)?);
        if flags.contains(NdefRecordFlags::CHUNKED) {
            return Err(NdefError("Chunked records not implemented".into()));
        }
        let type_length = *iter.next().ok_or(NdefRecordInvalid)? as usize;
        let payload_length = if flags.contains(NdefRecordFlags::SHORT) {
            *iter.next().ok_or(NdefRecordInvalid)? as usize
        } else {
            u32::from_be_bytes(
                take_and_advance(iter, 4)?
                    .try_into()
                    .or(Err(NdefRecordInvalid))?,
            ) as usize
        };
        let id_length = if flags.contains(NdefRecordFlags::ID) {
            *iter.next().ok_or(NdefRecordInvalid)? as usize
        } else {
            0
        };
        let payload_type = take_and_advance(iter, type_length)?;

        let _id = take_and_advance(iter, id_length)?; // Skip the ID, put iter at payload.
        let payload = take_and_advance(iter, payload_length)?;

        if TNF_WELLKNOWN == (flags & NdefRecordFlags::TNF_BITS).bits() {
            match *payload_type {
                [RTD_TEXT] => {
                    let flags = payload.first().ok_or(NdefRecordInvalid)?;
                    if *flags & RTD_TEXT_FLAG_UTF16 != 0 {
                        return Err(NdefError("UTF16 not supported".into()));
                    }
                    let language_code_length = (flags & RTD_TEXT_LC_LENGTH_MASK) as usize;
                    let language_code = std::str::from_utf8(
                        payload
                            .get(1..1 + language_code_length)
                            .ok_or(NdefRecordInvalid)?,
                    )
                    .or(Err(NdefRecordInvalid))?
                    .to_string();
                    let text = std::str::from_utf8(
                        payload
                            .get(1 + language_code_length..payload_length)
                            .ok_or(NdefRecordInvalid)?,
                    )
                    .or(Err(NdefRecordInvalid))?
                    .to_string();
                    Ok(NdefRecord::Text {
                        language_code,
                        text,
                    })
                }
                [RTD_URL] => todo!(),
                _ => Err(NdefError(format!(
                    "Well known type {} not implemented",
                    String::from_utf8_lossy(payload_type)
                ))),
            }
        } else {
            Err(NdefError(
                "Record type format invalid or not implemented".into(),
            ))
        }
    }
}

fn take_and_advance<'a>(iter: &mut Iter<'a, u8>, n: usize) -> Result<&'a [u8]> {
    let slice = iter.as_slice();
    if slice.len() < n {
        return Err(NdefRecordInvalid);
    }
    let (result, remaining) = slice.split_at(n);
    *iter = remaining.iter();
    Ok(result)
}

impl NdefMessage {
    pub fn content(&self) -> Result<Vec<u8>> {
        let mut message: Vec<Vec<u8>> = Vec::with_capacity(self.records.len());
        for (i, rec) in self.records.iter().enumerate() {
            message.push(rec.content(i == 0, i == self.records.len() - 1)?);
        }
        let mut message_content: Vec<u8> = Vec::with_capacity(message.iter().map(Vec::len).sum());
        for record_content in message {
            message_content.extend(record_content);
        }
        Ok(message_content)
    }
}

impl From<&[u8]> for NdefMessage {
    fn from(content: &[u8]) -> Self {
        let mut msg = NdefMessage::default();
        let mut iter = content.iter();
        while let Ok(rec) = NdefRecord::try_from(&mut iter) {
            msg.records.push(rec);
        }
        msg
    }
}

impl From<NdefRecord> for NdefMessage {
    fn from(rec: NdefRecord) -> Self {
        NdefMessage { records: vec![rec] }
    }
}

impl From<&[NdefRecord]> for NdefMessage {
    fn from(recs: &[NdefRecord]) -> Self {
        NdefMessage {
            records: recs.to_vec(),
        }
    }
}

impl IntoIterator for NdefMessage {
    type Item = NdefRecord;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.records.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn it_makes_text_record() -> Result<()> {
        let msg = NdefRecord::Text {
            language_code: "en".to_string(),
            text: "Hello rust!".to_string(),
        };
        let msg2 = NdefRecord::Text {
            language_code: "en".to_string(),
            text: "Hello world!".to_string(),
        };
        let content1 = msg.content_native()?;
        let content2 = msg.content(true, true)?;
        let content3 = msg2.content(true, true)?;
        assert_ne!(content2, content3);
        Ok(assert_eq!(content1, content2))
    }

    #[test]
    fn it_decodes_text_record() -> Result<()> {
        let msg = NdefRecord::Text {
            language_code: "en".to_string(),
            text: "Hello rust!".to_string(),
        };
        let content = msg.content(true, true)?;
        let msg2 = NdefRecord::try_from(&mut content.iter())?;
        Ok(assert_eq!(msg, msg2))
    }

    #[test]
    fn it_makes_message_from_one_record() -> Result<()> {
        let rec = NdefRecord::Text {
            language_code: "en".to_string(),
            text: "Hello rust!".to_string(),
        };
        let msg = NdefMessage {
            records: vec![rec.clone()],
        };

        let content1 = rec.content(true, true)?;
        let content2 = msg.content()?;
        Ok(assert_eq!(content1, content2))
    }

    #[test]
    fn it_makes_message_from_three_records() -> Result<()> {
        let rec1 = NdefRecord::Text {
            language_code: "en".to_string(),
            text: "Hello rust!".to_string(),
        };
        let rec2 = NdefRecord::Text {
            language_code: "en".to_string(),
            text: "Hello world!".to_string(),
        };
        let msg = NdefMessage {
            records: vec![rec1.clone(), rec1.clone(), rec2.clone()],
        };

        let content1 = rec1.content(true, false)?;
        let content2 = rec1.content(false, false)?;
        let content3 = rec2.content(false, true)?;
        let content = msg.content()?;
        assert_eq!(content1, content[..content1.len()]);
        assert_eq!(
            content2,
            content[content1.len()..content1.len() + content2.len()]
        );
        assert_ne!(
            content1,
            content[content1.len()..content1.len() + content2.len()]
        );
        Ok(assert_eq!(
            content3,
            content
                [content1.len() + content2.len()..content1.len() + content2.len() + content3.len()]
        ))
    }

    #[test]
    fn it_decodes_message_with_three_records() -> Result<()> {
        let rec1 = NdefRecord::Text {
            language_code: "en".to_string(),
            text: "Hello rust!".to_string(),
        };
        let rec2 = NdefRecord::Text {
            language_code: "en".to_string(),
            text: "Hello world!".to_string(),
        };
        let msg = NdefMessage {
            records: vec![rec1.clone(), rec1, rec2],
        };
        let content = msg.content()?;
        let msg2 = NdefMessage::from(content.as_slice());
        assert_eq!(msg2.records.len(), 3);
        Ok(assert_eq!(msg, msg2))
    }
}
