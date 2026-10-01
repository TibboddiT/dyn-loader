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

pub const TlsDestructorEvents = extern struct {
    destructor_count: u32 = 0,
    tls_value: u32 = 0,
};
