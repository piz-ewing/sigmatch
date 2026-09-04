use thiserror::Error;

use crate::Direction;

/// Error type for sigmatch library.
#[derive(Debug, Error)]
pub enum Error {
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

    #[error("string contains an embedded NUL byte")]
    InvalidString,

    #[error("invalid pattern: pattern length={pattern_len}, mask length={mask_len}")]
    InvalidPattern { pattern_len: usize, mask_len: usize },

    #[error("invalid signature token `{0}`")]
    InvalidSignatureToken(String),

    #[error("invalid mask character `{0}`")]
    InvalidMaskCharacter(char),

    #[error("search start 0x{start:X} is outside {direction} range 0x{low:X}..0x{high:X}")]
    SearchStartOutOfRange {
        start: usize,
        low: usize,
        high: usize,
        direction: Direction,
    },

    #[error("pattern length {0} exceeds bitmap bit size limit {1}")]
    PatternExceedsBitmapSize(usize, usize),

    #[error("search length {length} < pattern length {pattern}")]
    SearchLengthTooShort { length: usize, pattern: usize },

    #[error("search range requires too many cached pages: {pages}")]
    SearchRangeTooLarge { pages: usize },

    #[error("invalid reference encoding: field offset=0x{field_offset:X}, instruction size=0x{instruction_size:X}")]
    InvalidReferenceEncoding {
        field_offset: usize,
        instruction_size: usize,
    },

    #[error("reference query has no candidate pattern")]
    MissingReferencePattern,

    #[error("reference query has no address encoding")]
    MissingReferenceEncoding,

    #[error("pattern not found")]
    PatternNotFound,

    #[error("unexpected error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
