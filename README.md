# nfc-nci

These are the Rust-y "safe" bindings for NXP's [linux_nfc-nci library](https://github.com/NXPNFCLinux/linux_libnfc-nci).
They depend on the [low-level FFI bindings](https://github.com/ryanolf/nfc-nci-sys/) which are at present specified as a path dependency.

This code doesn't completely cover the capability in linux_nfc-nci yet, but the bits here (reading and writing NDEF) are quite functional.
