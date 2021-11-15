
#![feature(derive_default_enum, iter_advance_by)]
#![allow(missing_docs)]

use bitflags::bitflags;
mod ndef;
pub use ndef::*;

use nfc_nci_sys as raw;
use thiserror::Error;

use libffi::high::{Closure0, Closure1};
use num_traits::FromPrimitive;

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

    pub fn write_ndef(&self, ndef: NdefMessage) -> Result<()> {
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

    pub fn read_ndef(&self) -> Result<NdefMessage> {
        let ndef_info = self.ndef_info()?;
        let mut ndef_content: Vec<u8> =
            Vec::with_capacity(ndef_info.current_ndef_length.try_into().unwrap());
        let mut _ndef_type = raw::nfc_friendly_type_t::default();
        let ndef_len = unsafe {
            // This writes into the content vector via raw pointer
            raw::nfcTag_readNdef(
                self.handle,
                ndef_content.as_mut_ptr(),
                ndef_info.current_ndef_length,
                &mut _ndef_type,
            )
        };

        if ndef_len < 0 {
            return Err(TagError("Failed to read NDEF message from tag".into()));
        }
        // We have to tell the vector that we wrote in the space we allocated
        unsafe { ndef_content.set_len(ndef_len.try_into().unwrap()) };
        Ok(ndef_content.as_slice().into())
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

struct OnDepartureCallback<'a> {
    /// Create a raw pointer with Box::into_raw.
    _rust_closure: Box<dyn Fn()>,
    c_closure: Closure0<'a, ()>,
}

#[derive(Default)]
pub struct NFCManager<'a> {
    on_arrival: Option<OnArrivalCallback<'a>>,
    on_departure: Option<OnDepartureCallback<'a>>,
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

    pub fn register_tag_callbacks(
        &mut self,
        on_arrival: Option<impl Fn(NfcTag) + 'static>,
        on_departure: Option<impl Fn() + 'static>,
    ) {
        if let Some(cb) = on_arrival {
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
        if let Some(cb) = on_departure {
            let rust_closure = Box::new(move || cb());
            let rust_closure_ptr = Box::into_raw(rust_closure);
            let c_closure = unsafe { Closure0::new(&*rust_closure_ptr) };
            self.on_departure = Some(OnDepartureCallback {
                _rust_closure: unsafe { Box::from_raw(rust_closure_ptr) },
                c_closure,
            });
            self.tag_callbacks.onTagDeparture = unsafe {
                Some(std::mem::transmute(
                    *self.on_departure.as_ref().unwrap().c_closure.code_ptr(),
                ))
            }
        }

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

    pub fn get_num_tags(&self) -> usize {
        unsafe {
            raw::nfcManager_getNumTags() as usize
        }
    }

    pub fn get_next_tag(&self) -> Result<()> {
        if unsafe { raw::nfcManager_selectNextTag() } == 0 {
            Ok(())
        } else {
            Err(NFCError::ManagerError("Failure selecting next tag".into()))
        }
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
    #[error("Error in NDEF: Record invalid")]
    NdefRecordInvalid,
}