use core::ptr::NonNull;

use aliasable::boxed::AliasableBox;
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
    #[derive(PartialEq, Eq, Hash, Debug, Clone, Copy)]
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
#[derive(Clone)]
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

impl From<&raw::nfc_tag_info_t> for NfcTag {
    fn from(tag_info: &raw::nfc_tag_info_t) -> Self {
        Self {
            technology: NFATechnology::from_bits_truncate(tag_info.technology),
            handle: tag_info.handle,
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
            is_ndef: ndef_info.is_ndef != 0,
            is_writable: ndef_info.is_writable != 0,
            current_ndef_length: ndef_info.current_ndef_length,
            max_ndef_length: ndef_info.max_ndef_length,
        }
    }
}

struct OnArrivalCallback {
    // Make sure c_closure is dropped before _rust_closure as it references it
    c_closure: Closure1<'static, *mut raw::nfc_tag_info_t, ()>,
    _rust_closure: AliasableBox<dyn Fn(*mut raw::nfc_tag_info_t) + Send>,
    // _pin: PhantomPinned,
}

struct OnDepartureCallback {
    // Make sure c_closure is dropped before _rust_closure as it references it
    c_closure: Closure0<'static, ()>,
    _rust_closure: AliasableBox<dyn Fn() + Send>,
    // _pin: PhantomPinned,
}

// SAFETY
// These are "read only" except when created in register_tag_callbacks
// The only thread that mutates anything is the NFC library thread.
unsafe impl Send for OnArrivalCallback {}
unsafe impl Send for OnDepartureCallback {}
unsafe impl Sync for OnArrivalCallback {}
unsafe impl Sync for OnDepartureCallback {}

#[derive(Default)]
pub struct NFCManager {
    on_arrival: Option<OnArrivalCallback>,
    on_departure: Option<OnDepartureCallback>,
    tag_callbacks: raw::nfcTagCallback_t,
}

impl NFCManager {
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
        on_arrival: Option<impl Fn(NfcTag) + 'static + Send>,
        on_departure: Option<impl Fn() + 'static + Send>,
    ) {
        if let Some(cb) = on_arrival {
            // SAFETY: tag_info is a raw pointer to a C struct provided by the
            // NFC library. We count on them to assure it is non-null and
            // aligned and can be dereferenced
            let rust_closure_ptr = NonNull::new(Box::into_raw(Box::new(
                move |tag_info: *mut raw::nfc_tag_info_t| cb(unsafe { (&*tag_info).into() }),
            )))
            .expect("Box::into_raw guarantees nonnull pointer");

            // SAFETY: the pointer derives from Box::into_raw, so it's valid.
            // The referenced data is going to be boxed in a private field where
            // it is not mutated and is freed after the c-closure
            let c_closure = Closure1::new(unsafe { rust_closure_ptr.as_ref() });
            let on_arrival = OnArrivalCallback {
                c_closure,
                // SAFETY: ptr is created by Box::into_raw above and is
                // unaltered. We use AliasableBox to assert that the pointer is
                // not "unique"
                _rust_closure: AliasableBox::from_unique(unsafe {
                    Box::from_raw(rust_closure_ptr.as_ptr())
                }),
                // _pin: PhantomPinned,
            };

            // SAFETY: Here we get a raw pointer to the C fn inside the
            // c_closure. As long as c_closure exists, which it should because
            // we're storing it in this struct, this address should be stable.
            self.tag_callbacks.onTagArrival = unsafe {
                Some(std::mem::transmute::<
                    libffi::high::FnPtr1<'_, *mut nfc_nci_sys::nfc_tag_info_t, ()>,
                    unsafe extern "C" fn(*mut nfc_nci_sys::nfc_tag_info_t),
                >(*on_arrival.c_closure.code_ptr()))
            };
            self.on_arrival = Some(on_arrival);
        }
        if let Some(cb) = on_departure {
            let rust_closure_ptr = NonNull::new(Box::into_raw(Box::new(cb)))
                .expect("Box::into_raw guarantees nonnull pointer");

            // SAFETY: the pointer derives from Box::into_raw, so it's valid.
            // The referenced data is going to be boxed in a private field where
            // it is not mutated and is freed after the c-closure
            let c_closure = Closure0::new(unsafe { rust_closure_ptr.as_ref() });
            let on_departure = OnDepartureCallback {
                c_closure,
                // SAFETY: ptr is created by Box::into_raw above and is
                // unaltered. We use AliasableBox to assert that the pointer is
                // not "unique"
                _rust_closure: AliasableBox::from_unique(unsafe {
                    Box::from_raw(rust_closure_ptr.as_ptr())
                }),
                // _pin: PhantomPinned,
            };
            self.tag_callbacks.onTagDeparture = unsafe {
                Some(std::mem::transmute::<
                    libffi::high::FnPtr0<'_, ()>,
                    unsafe extern "C" fn(),
                >(*on_departure.c_closure.code_ptr()))
            };
            self.on_departure = Some(on_departure);
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
        unsafe { raw::nfcManager_getNumTags() as usize }
    }

    pub fn get_next_tag(&self) -> Result<()> {
        if unsafe { raw::nfcManager_selectNextTag() } == 0 {
            Ok(())
        } else {
            Err(NFCError::ManagerError("Failure selecting next tag".into()))
        }
    }
}

impl Drop for NFCManager {
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
