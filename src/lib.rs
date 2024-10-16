//! # NFC-NCI
//!
//! These are the Rust-y "safe" bindings for NXP's [linux_nfc-nci library](https://github.com/NXPNFCLinux/linux_libnfc-nci).
//! They depend on the [low-level FFI bindings](https://github.com/ryanolf/nfc-nci-sys/) which are at present specified as a path dependency.
//!
//! This code doesn't completely cover the capability in linux_nfc-nci yet, but the bits here (reading and writing NDEF) are quite functional.
//!
//! ## Features
//!
//! - NFC tag reading and writing
//! - NDEF message parsing and creation
//!
//! ## Usage
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! nfc-nci = "0.1.1"
//! ```
//!
//! Then use the crate in your Rust code:
//!
//! ```rust
//! use nfc_nci::{NFCManager, NFATechnology};
//!
//! let mut manager = NFCManager::initialize()?;
//! let arrival_callback = move |_tag| {
//!     println!("Tag arrived.");
//! };
//! let departure_callback = move || {
//!     println!("Tag departed");
//! };
//! manager.register_tag_callbacks(Some(arrival_callback), Some(departure_callback));
//! manager.enable_discovery(None, Some(true), None, None);
//! ```
//!
//! For more detailed examples, see the [examples](https://github.com/ryanolf/nfc-nci/tree/main/examples) directory.

#[macro_use]
extern crate num_derive;

use bitflags::bitflags;
use core::ptr::NonNull;
use ndef::NdefMessage;

use nfc_nci_sys as raw;
use thiserror::Error;

use libffi::high::{Closure0, Closure1};
use num_traits::FromPrimitive;

pub mod ndef;

type Result<T> = std::result::Result<T, NFCError>;

bitflags! {
    #[derive(Clone, Copy)]
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

/// The NFC protocol used by the tag according to the reader
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
    technology: NFATechnology,
    /// The handle of the tag
    handle: u32,
    /// The uid of the tag (hexadecimal)
    uid: Vec<u8>,
    /// The tag protocol
    protocol: NFCProtocol,
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
    /// Returns the technology of the tag
    pub fn technology(&self) -> NFATechnology {
        self.technology
    }

    /// Returns the handle of the tag
    pub fn handle(&self) -> u32 {
        self.handle
    }

    /// Returns a reference to the UID of the tag
    pub fn uid(&self) -> &[u8] {
        &self.uid
    }

    /// Returns the protocol of the tag
    pub fn protocol(&self) -> NFCProtocol {
        self.protocol
    }

    /// If a tag that can be Ndef is found, returns NdefInfo, otherwise returns an error
    pub fn ndef_info(&self) -> Result<NdefInfo> {
        let mut ndef_info: raw::ndef_info_t = Default::default();
        unsafe { raw::nfcTag_isNdef(self.handle, &mut ndef_info) };
        let ndef_info: NdefInfo = (&ndef_info).into();
        if ndef_info.max_ndef_length == 0 {
            Err(NFCError::TagError("Could not obtain tag info.".into()))
        } else {
            Ok(ndef_info)
        }
    }

    /// Formats the tag, erasing all data on it
    pub fn format(&self) -> Result<()> {
        if unsafe { raw::nfcTag_formatTag(self.handle) } != 0 {
            Err(NFCError::TagError("Failed to format tag".into()))
        } else {
            Ok(())
        }
    }

    /// Writes an NDEF message to the tag
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
            return Err(NFCError::TagError("Failed to write to tag".into()));
        }
        Ok(())
    }

    /// Reads the NDEF message from the tag
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
            return Err(NFCError::TagError(
                "Failed to read NDEF message from tag".into(),
            ));
        }
        // We have to tell the vector that we wrote in the space we allocated
        unsafe { ndef_content.set_len(ndef_len.try_into().unwrap()) };
        Ok(ndef_content.as_slice().into())
    }
}

/// Information about the NDEF capabilities of the tag
pub struct NdefInfo {
    is_ndef: bool,
    is_writable: bool,
    current_ndef_length: u32,
    max_ndef_length: u32,
}

impl NdefInfo {
    /// Returns whether the tag contains an NDEF message
    pub fn is_ndef(&self) -> bool {
        self.is_ndef
    }

    /// Returns whether the tag is writable
    pub fn is_writable(&self) -> bool {
        self.is_writable
    }

    /// Returns the current length of the NDEF message on the tag
    pub fn current_ndef_length(&self) -> u32 {
        self.current_ndef_length
    }

    /// Returns the maximum length of an NDEF message that can be written to the tag
    pub fn max_ndef_length(&self) -> u32 {
        self.max_ndef_length
    }
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

/// A NonNull pointer that is derived from Box::into_raw and handles dropping the
/// original Box/deallocating the memory. It "owns" the pointer memory.
struct NonNullOwned<T: ?Sized>(NonNull<T>);

impl<T> NonNullOwned<T> {
    fn new(value: T) -> Self {
        Self(
            NonNull::new(Box::into_raw(Box::new(value)))
                .expect("Box::into_raw guarantees nonnull pointer"),
        )
    }
}

impl<T: ?Sized> Drop for NonNullOwned<T> {
    fn drop(&mut self) {
        // SAFETY: The pointer should be generated by Box::into_raw
        let _ = unsafe { Box::from_raw(self.0.as_ptr()) };
    }
}

/// Self-referential struct to store the owned on-arrival rust callback along
/// with the c-closure containing reference to the callback.
struct OnArrivalCallback {
    // Make sure c_closure is dropped before _rust_closure as former references
    // memory "owned" by the later
    /// The c-closure containing reference to the callback
    c_closure: Closure1<'static, *mut raw::nfc_tag_info_t, ()>,

    /// The "owned" rust callback
    ///
    /// We store the callback in NonNullOwned rather than a Box because the
    /// compiler assumes that when Box is created (or moved) it is a unique
    /// (unaliased) reference to the allocation and can optimize for this,
    /// leading to potential undefined behavior if this is not the case. In this
    /// case, the reference in the c-closure is obtained via a raw pointer (to
    /// get around lifetime rules with self-referential structs) and so the Box
    /// would not be a unique reference.
    _owned_closure: NonNullOwned<dyn Fn(*mut raw::nfc_tag_info_t) + Send + Sync>,
}

impl OnArrivalCallback {
    fn new(cb: impl Fn(*mut raw::nfc_tag_info_t) + 'static + Send + Sync) -> Self {
        let rust_closure_ptr = NonNullOwned::new(cb);

        // SAFETY: the pointer derives from Box::into_raw via NonNullOwned, so
        // it's valid. The referenced data allocation will remain valid until
        // the closure is dropped.
        let c_closure = Closure1::new(unsafe { rust_closure_ptr.0.as_ref() });
        OnArrivalCallback {
            c_closure,
            // Re-wrap the pointer so that compiler can coerce <impl Fn()> to <dyn Fn()>
            _owned_closure: NonNullOwned(rust_closure_ptr.0),
        }
    }

    fn code_ptr(&self) -> unsafe extern "C" fn(*mut nfc_nci_sys::nfc_tag_info_t) {
        // SAFETY: FnPtrX is a transparent wrapper around a raw pointer to a
        // C and can be safely transmuted to the inner type
        unsafe { std::mem::transmute(self.c_closure.code_ptr()) }
    }
}

/// Self-referential struct to store the owned rust on-departure callback along
/// with the c-closure containing reference to the callback.
struct OnDepartureCallback {
    // Make sure c_closure is dropped before _rust_closure as it references it
    c_closure: Closure0<'static, ()>,
    _rust_closure: NonNullOwned<dyn Fn() + Send + Sync>,
}
impl OnDepartureCallback {
    fn new(cb: impl Fn() + 'static + Send + Sync) -> Self {
        let rust_closure_ptr = NonNullOwned::new(cb);

        // SAFETY: the pointer derives from Box::into_raw via NonNullOwned, so
        // it's valid. The referenced data allocation will remain valid until
        // the closure is dropped.
        let c_closure = Closure0::new(unsafe { rust_closure_ptr.0.as_ref() });
        OnDepartureCallback {
            c_closure,
            // Re-wrap the pointer so that compiler can coerce <impl Fn()> to <dyn Fn()>
            _rust_closure: NonNullOwned(rust_closure_ptr.0),
        }
    }

    fn code_ptr(&self) -> unsafe extern "C" fn() {
        // SAFETY: FnPtrX is a transparent wrapper around a raw pointer to a
        // C and can be safely transmuted to the inner type
        unsafe { std::mem::transmute(self.c_closure.code_ptr()) }
    }
}

// SAFETY These structs are not automatically thread safe because they contain a
// raw pointer and !Send + !Sync Closure type. However, the raw pointer is in a
// private field and is never modified nor even accessed until drop. The Closure
// is accessed from the extern C code (which spawns threads) but is never
// modified.
unsafe impl Send for OnArrivalCallback {}
unsafe impl Send for OnDepartureCallback {}
unsafe impl Sync for OnArrivalCallback {}
unsafe impl Sync for OnDepartureCallback {}

/// The NFC manager, which handles tag discovery and callbacks.
///
/// The methods are safe wrappers with native Rust types that mirror the C API.
/// See the C API documentation for more details on the methods and function arguements.
#[derive(Default)]
pub struct NFCManager {
    /// The tag callbacks - this should drop first as it can have fn ptrs to the
    /// callbacks which are owned by the other structs
    tag_callbacks: raw::nfcTagCallback_t,
    on_arrival: Option<OnArrivalCallback>,
    on_departure: Option<OnDepartureCallback>,
}

impl NFCManager {
    /// Initializes the NFC manager.
    pub fn initialize() -> Result<Self> {
        if unsafe { raw::nfcManager_doInitialize() } != 0 {
            return Err(NFCError::ManagerError("Initialization failed".into()));
        }
        Ok(NFCManager::default())
    }

    fn deinitialize(&mut self) -> Result<()> {
        if unsafe { raw::nfcManager_doDeinitialize() } != 0 {
            return Err(NFCError::ManagerError("Deinitialization failed".into()));
        }
        Ok(())
    }

    /// Registers callbacks for tag arrival and departure.
    pub fn register_tag_callbacks(
        &mut self,
        on_arrival: Option<impl Fn(NfcTag) + 'static + Send + Sync>,
        on_departure: Option<impl Fn() + 'static + Send + Sync>,
    ) {
        if let Some(cb) = on_arrival {
            let rust_callback =
                OnArrivalCallback::new(move |tag_info: *mut raw::nfc_tag_info_t| {
                    cb(unsafe { (&*tag_info).into() })
                });

            self.tag_callbacks.onTagArrival = Some(rust_callback.code_ptr());
            self.on_arrival = Some(rust_callback);
        }
        if let Some(cb) = on_departure {
            let rust_callback = OnDepartureCallback::new(cb);
            self.tag_callbacks.onTagDeparture = Some(rust_callback.code_ptr());
            self.on_departure = Some(rust_callback);
        }

        // SAFETY: self.tag_callbacks contains valid pointers that will live
        // until the nfcManager is de-initialized in the drop impl
        unsafe { raw::nfcManager_registerTagCallback(&mut self.tag_callbacks) };
    }

    /// Enables tag discovery.
    ///
    /// `technology` is the technology to discover.
    /// `reader_only_q` is whether the reader should only be used for reading (No P2P or HCE)
    /// `enable_host_routing_q` indicates if enable host card emualtion
    /// `force_restart_q` is whether the discovery should be forced to restart.
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

    /// Returns the number of tags currently connected.
    pub fn get_num_tags(&self) -> usize {
        unsafe { raw::nfcManager_getNumTags() as usize }
    }

    /// Selects the next tag.
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
