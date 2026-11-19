use thiserror::Error;

use crate::Direction;

/// Errors from module binding, pattern parsing, and queries.
#[derive(Debug, Error)]
pub enum Error {
    /// `GetModuleHandleW` or `GetModuleHandleExW` failed, or returned a null
    /// handle. The name is the module the seeker tried to bind.
    #[error("failed to get module handle for `{0}`")]
    GetModuleHandleFailed(String),

    /// The module base does not start with a readable DOS header carrying the
    /// `MZ` signature.
    #[error("module `{0}` has invalid DOS header")]
    InvalidDosHeader(String),

    /// The DOS header points at an NT header that cannot be read, has the
    /// wrong signature, or declares an optional header magic that does not
    /// match the target architecture.
    #[error("module `{0}` has invalid NT header")]
    InvalidNtHeader(String),

    /// The optional header reports `SizeOfImage` of 0, or base plus size
    /// overflows `usize`.
    #[error("module `{0}` has no size")]
    ModuleSizeZero(String),

    /// `in_section` or `find_in` named a section that is not in the section
    /// table. The name is the one that was asked for.
    #[error("section `{0}` not found")]
    SectionNotFound(String),

    /// A section header describes a range outside the image, or computing
    /// that range overflowed.
    #[error("section `{0}` out of bounds")]
    SectionOutOfBounds(String),

    /// A query ran on a `Seeker` that has no module bound.
    #[error("seeker is not initialized")]
    Uninitialized,

    /// The literal passed to `string` or `strings` contains a NUL byte, so a
    /// NUL-terminated search would match the wrong bytes.
    #[error("string contains an embedded NUL byte")]
    InvalidString,

    /// The byte list and the mask have different lengths, or the pattern is
    /// empty.
    #[error("invalid pattern: pattern length={pattern_len}, mask length={mask_len}")]
    InvalidPattern {
        /// Length of the byte list.
        pattern_len: usize,
        /// Length of the mask.
        mask_len: usize,
    },

    /// A token in an IDA or x64dbg signature is neither `?`, `??`, nor two
    /// hex digits.
    #[error("invalid signature token `{0}`")]
    InvalidSignatureToken(String),

    /// A mask passed to `Pattern::masked` contains a character other than
    /// `x` or `?`.
    #[error("invalid mask character `{0}`")]
    InvalidMaskCharacter(char),

    /// `forward_from` or `backward_from` received a start address outside the
    /// section or module being scanned. `high` is the last valid address, not
    /// an exclusive bound.
    #[error("search start 0x{start:X} is outside {direction} range 0x{low:X}..0x{high:X}")]
    SearchStartOutOfRange {
        /// Address the query was told to start at.
        start: usize,
        /// First address of the allowed window.
        low: usize,
        /// Last address of the allowed window.
        high: usize,
        /// Direction of the query that rejected the start.
        direction: Direction,
    },

    /// `Pattern::bitmap` received more bytes than the bit mask can describe.
    /// The fields are the byte count and the bit count of `usize`.
    #[error("pattern length {0} exceeds bitmap bit size limit {1}")]
    PatternExceedsBitmapSize(usize, usize),

    /// The scan window is shorter than the pattern, so no candidate can fit.
    #[error("search length {length} < pattern length {pattern}")]
    SearchLengthTooShort {
        /// Bytes available in the scan window.
        length: usize,
        /// Bytes the pattern needs.
        pattern: usize,
    },

    /// The scan window covers more pages than the readability cache holds. A
    /// query this wide has to be narrowed with `in_section` or `within`.
    #[error("search range requires too many cached pages: {pages}")]
    SearchRangeTooLarge {
        /// Pages the query would have to cache.
        pages: usize,
    },

    /// A `ReferenceEncoding` places its displacement or operand field outside
    /// the pattern, or past the end of the instruction it describes.
    #[error("invalid reference encoding: field offset=0x{field_offset:X}, instruction size=0x{instruction_size:X}")]
    InvalidReferenceEncoding {
        /// Offset of the displacement or operand field inside the pattern.
        field_offset: usize,
        /// Instruction length the encoding declares.
        instruction_size: usize,
    },

    /// `ReferenceQuery::all` ran without `matching`, so there is no candidate
    /// pattern to look for.
    #[error("reference query has no candidate pattern")]
    MissingReferencePattern,

    /// `ReferenceQuery::all` ran without `using`, so candidate instructions
    /// cannot be decoded.
    #[error("reference query has no address encoding")]
    MissingReferenceEncoding,

    /// The scan reached the end of its window without a match.
    #[error("pattern not found")]
    PatternNotFound,

    /// Escape hatch for failures this crate does not model. Nothing in
    /// sigmatch builds it today; callers can use it to wrap their own errors.
    #[error("unexpected error: {0}")]
    Other(String),
}

/// `Result` with [`enum@Error`] as the error type.
pub type Result<T> = std::result::Result<T, Error>;
