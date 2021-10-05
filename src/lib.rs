#[allow(missing_docs)]
use bitflags::bitflags;
use nfc_nci_sys as raw;
use thiserror::Error;

use libffi::high::Closure1;
use num_traits::FromPrimitive;
use std::ffi::CString;

#[macro_use]
extern crate num_derive;

use NFCError::*;
type Result<T> = std::result::Result<T, NFCError>;

bitflags! {
    pub struct NFATechnology: u32 {
        const A = 1;
        const B = 2;
        const F = 4;
        const ISO15693 = 8;
        const KOVIO = 32;
        const A_ACTIVE = 64;
        const F_ACTIVE = 128;
        const ALL = 255;
    }
}

#[derive(FromPrimitive, Debug, PartialEq, Copy, Clone)]
pub enum NFCProtocol {
    Unknown = 0,
    Type1Tag = 1,
    Type2Tag = 2,
    Type3Tag = 3,
    IsoDep = 4,
    Iso15693 = 6,
    MiFare = 128,
}

#[derive(Debug, PartialEq, Clone)]
pub enum NdefType {
    /// NDEF text: NFC Forum well-known type + RTD: 0x55
    Text{
        language_code: String,
        text: String
    },
    /// NDEF URL: NFC Forum well-known type + RTD: 0x54
    Url(String),
    /// Handover select package
    HandoverSelect,
    /// Handover request package
    HandoverRequest,
    /// Unable to decode
    Other,
}

impl NdefType {
    fn content(&self) -> Result<Vec<std::os::raw::c_uchar>> {
        let mut content: Vec<std::os::raw::c_uchar>;
        let content_len;
        match self {
            NdefType::Text{language_code, text} => {
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
            Err(TagError("Failed to encode NDEF text.".into()))
        } else {
            unsafe { content.set_len(content_len.try_into().unwrap()) };
            Ok(content)
        }
    }
}

impl TryFrom<(u32, Vec<std::os::raw::c_uchar>)> for NdefType {
    type Error = NFCError;

    fn try_from(type_content: (u32, Vec<std::os::raw::c_uchar>)) -> Result<Self> {
        let (kind, mut content) = type_content;
        match kind {
            0 => {
                // The text content is less than the ndef content in size. Use u8 for conversion to CString.
                let mut text_content: Vec<u8> = Vec::with_capacity(content.len());
                let mut lc_content: Vec<u8> = Vec::with_capacity(content.len());
                let (text_len, lc_len);
                unsafe {
                    text_len = raw::ndef_readText(
                        content.as_mut_ptr(),
                        content.len().try_into().unwrap(),
                        text_content.as_mut_ptr() as *mut std::os::raw::c_char,
                        text_content.capacity().try_into().unwrap(),
                    );
                    lc_len = raw::ndef_readLanguageCode(
                        content.as_mut_ptr(),
                        content.len().try_into().unwrap(),
                        lc_content.as_mut_ptr() as *mut std::os::raw::c_char,
                        lc_content.capacity().try_into().unwrap(),
                    )
                };
                if text_len > -1 && lc_len > -1 {
                    unsafe {
                        text_content.set_len(text_len.try_into().unwrap());
                        lc_content.set_len(lc_len.try_into().unwrap());
                    };
                    // let text = CString::new(&text_content[..text_len.try_into().unwrap()]).unwrap();
                    let text = CString::new(text_content).unwrap();
                    let language_code = CString::new(lc_content).unwrap();
                    Ok(Self::Text{
                        language_code: language_code.to_str().unwrap().into(),
                        text: text.to_str().unwrap().into(),
                    })
                } else {
                    Err(NdefError("Failed to extract text from NDEF".into()))
                }
            },
            _ => todo!()
        }
    }
}

/// Description of the tag found by the reader
pub struct NfcTag {
    /// The technology of the tag
    pub technology: NFATechnology,
    /// The handle of the tag
    pub handle: u32,
    /// The uid of the tag (hexadecimal)
    pub uid: Vec<u8>,
    /// The tag protocol
    pub protocol: NFCProtocol,
}

impl From<*mut raw::nfc_tag_info_t> for NfcTag {
    fn from(tag_info_ptr: *mut raw::nfc_tag_info_t) -> Self {
        // How to deal with panics/errors?
        let tag_info = unsafe { &*tag_info_ptr };
        Self {
            technology: NFATechnology::from_bits_truncate(tag_info.technology),
            handle: tag_info.handle.into(),
            uid: Vec::from(&tag_info.uid[..tag_info.uid_length.try_into().unwrap()]),
            protocol: NFCProtocol::from_u8(tag_info.protocol).unwrap(),
        }
    }
}

impl NfcTag {
    /// If a tag that can be Ndef is found, returns NdefInfo
    pub fn ndef_info(&self) -> Result<NdefInfo> {
        let mut ndef_info: raw::ndef_info_t = Default::default();
        unsafe { raw::nfcTag_isNdef(self.handle, &mut ndef_info) };
        let ndef_info: NdefInfo = (&ndef_info).into();
        if ndef_info.max_ndef_length == 0 {
            Err(TagError("Could not obtain tag info.".into()))
        } else {
            Ok(ndef_info)
        }
    }

    pub fn format(&self) -> Result<()> {
        if unsafe { raw::nfcTag_formatTag(self.handle) } != 0 {
            Err(TagError("Failed to format tag".into()))
        } else {
            Ok(())
        }
    }

    pub fn write_ndef(&self, ndef: NdefType) -> Result<()> {
        let mut ndef_content = ndef.content()?;
        let res = unsafe {
            raw::nfcTag_writeNdef(
                self.handle,
                ndef_content.as_mut_ptr(),
                ndef_content.len().try_into().unwrap(),
            )
        };
        if res != 0 {
            return Err(TagError("Failed to write to tag".into()));
        }
        Ok(())
    }

    pub fn read_ndef(&self) -> Result<NdefType> {
        let ndef_info = self.ndef_info()?;
        let mut ndef_content: Vec<std::os::raw::c_uchar> =
            Vec::with_capacity(ndef_info.current_ndef_length.try_into().unwrap());
        let mut ndef_type: raw::nfc_friendly_type_t = Default::default();
        let ndef_len = unsafe {
            // This writes into the content vector via raw pointer
            raw::nfcTag_readNdef(
                self.handle,
                ndef_content.as_mut_ptr(),
                ndef_info.current_ndef_length,
                &mut ndef_type,
            )
        };

        if ndef_len == -1 {
            return Err(TagError("Failed to read NDEF text record from tag".into()));
        }
        // We have to tell the vector that we wrote in the space we allocated
        unsafe { ndef_content.set_len(ndef_len.try_into().unwrap()) };
        NdefType::try_from((ndef_type, ndef_content))
    }
}

pub struct NdefInfo {
    pub is_ndef: bool,
    pub is_writable: bool,
    pub current_ndef_length: u32,
    pub max_ndef_length: u32,
}

impl From<&raw::ndef_info_t> for NdefInfo {
    fn from(ndef_info: &raw::ndef_info_t) -> Self {
        Self {
            is_ndef: if ndef_info.is_ndef == 0 { false } else { true },
            is_writable: if ndef_info.is_writable == 0 {
                false
            } else {
                true
            },
            current_ndef_length: ndef_info.current_ndef_length.into(),
            max_ndef_length: ndef_info.max_ndef_length.into(),
        }
    }
}

struct OnArrivalCallback<'a> {
    /// Create a raw pointer with Box::into_raw.
    _rust_closure: Box<dyn Fn(*mut raw::nfc_tag_info_t)>,
    c_closure: Closure1<'a, *mut raw::nfc_tag_info_t, ()>,
}

#[derive(Default)]
pub struct NFCManager<'a> {
    on_arrival: Option<OnArrivalCallback<'a>>,
    tag_callbacks: raw::nfcTagCallback_t,
}

impl<'a> NFCManager<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn initialize(&mut self) -> Result<()> {
        if unsafe { raw::nfcManager_doInitialize() } != 0 {
            return Err(ManagerError("Initialization failed".into()));
        }
        Ok(())
    }

    pub fn deinitialize(&mut self) -> Result<()> {
        if unsafe { raw::nfcManager_doDeinitialize() } != 0 {
            return Err(ManagerError("Deinitialization failed".into()));
        }
        Ok(())
    }

    pub fn register_tag_callbacks(&mut self, on_arrival: Option<impl Fn(NfcTag) + 'static>) {
        match on_arrival {
            Some(cb) => {
                // Wrap the given callback in a callback that transforms the tag info
                let rust_closure =
                    Box::new(move |tag_info: *mut raw::nfc_tag_info_t| cb(tag_info.into()));
                // We need to store both this (rust) closure as well as a C fn
                // pointer callback that references it. Rust's lifetime rules
                // don't recognize that the Boxed closure lives as long as Box
                // (not just the borrow for the C fn pointer) so we have to use
                // a raw pointer here.
                let rust_closure_ptr = Box::into_raw(rust_closure);
                let c_closure = unsafe { Closure1::new(&*rust_closure_ptr) };
                self.on_arrival = Some(OnArrivalCallback {
                    _rust_closure: unsafe { Box::from_raw(rust_closure_ptr) },
                    c_closure,
                });

                // Here we get a raw pointer to the C fn inside the c_closure.
                // As long as c_closure exists, which it should because we're
                // storing it in this struct, this address should be stable.
                self.tag_callbacks.onTagArrival = unsafe {
                    Some(std::mem::transmute(
                        *self.on_arrival.as_ref().unwrap().c_closure.code_ptr(),
                    ))
                }
            }
            None => (),
        };

        unsafe { raw::nfcManager_registerTagCallback(&mut self.tag_callbacks) };
    }

    pub fn enable_discovery(
        &mut self,
        technology: Option<NFATechnology>,
        reader_only_q: Option<bool>,
        enable_host_routing_q: Option<bool>,
        force_restart_q: Option<bool>,
    ) {
        unsafe {
            raw::nfcManager_enableDiscovery(
                technology.map(|t| t.bits() as i32).unwrap_or(-1),
                reader_only_q.unwrap_or(false).into(),
                enable_host_routing_q.unwrap_or(false).into(),
                force_restart_q.unwrap_or(false).into(),
            )
        };
    }
}

impl<'a> Drop for NFCManager<'a> {
    fn drop(&mut self) {
        self.deinitialize().ok();
    }
}

#[derive(Error, Debug)]
pub enum NFCError {
    #[error("Error in NFC Manager: {0}")]
    ManagerError(String),
    #[error("Error in NFC Tag: {0}")]
    TagError(String),
    #[error("Error in NDEF: {0}")]
    NdefError(String),
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
