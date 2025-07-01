use thiserror::Error;

use crate::Direction;

/// Error type for sigmatch library.
#[derive(Debug, Error)]
pub enum Error {
    #[error("module `{0}` not found")]
    ModuleNotFound(String),

    #[error("failed to get module handle for `{0}`")]
    GetModuleHandleFailed(String),

    #[error("module `{0}` has invalid DOS header")]
    InvalidDosHeader(String),

    #[error("module `{0}` has invalid NT header")]
    InvalidNtHeader(String),

    #[error("module `{0}` has no size")]
    ModuleSizeZero(String),

    #[error("section `{0}` not found")]
    SectionNotFound(String),

    #[error("section `{0}` out of bounds")]
    SectionOutOfBounds(String),

    #[error("seeker is not initialized")]
    Uninitialized,

    #[error("invalid pattern({0}) or mask({1})")]
    InvalidPattern(usize, usize),

    #[error("search range with offset is out of module bounds: start=0x{0:X}, length=0x{1:X}, offset=0x{2:X}, reverse={3}")]
    OffsetOutOfModule(usize, usize, usize, Direction),

    #[error("search range with offset is out of section bounds: start=0x{0:X}, length=0x{1:X}, offset=0x{2:X}, reverse={3}")]
    OffsetOutOfSection(usize, usize, usize, Direction),

    #[error("invalid search range")]
    InvalidAdjustRange,

    #[error("invalid address result")]
    InvalidAddr,

    #[error("sig is not a valid hex pattern")]
    InvalidSigHex,

    #[error("pattern length {0} exceeds bitmap bit size limit {1}")]
    PatternExceedsBitmapSize(usize, usize),

    #[error("search length {0} < pattern length {1}")]
    SearchLengthTooShort(usize, usize),

    //
    #[error("pattern not found")]
    PatternNotFound,

    #[error("unexpected error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
