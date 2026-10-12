//! C layouts from `abi.h`. Records cross native function calls and remain owned
//! by the Zig test; finalization records must outlive every handle using them.

pub const LibraryState = extern struct {
    initialized_global: u32,
    zeroed_global: u32,
    tls_value: u32,
    constructor_count: u32,
};

pub const FinalizationEvents = extern struct {
    finalizer_count: u32 = 0,
    initialized_global: u32 = 0,
    zeroed_global: u32 = 0,
    tls_value: u32 = 0,
};
