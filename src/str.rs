use windows::core::PCWSTR;

pub struct PCWSTRWrapper(Vec<u16>);

impl PCWSTRWrapper {
    /// Get a raw PCWSTR to the string
    /// While this is possible to do using e.g. PCWSTR::from_raw, these are not marked as
    /// unsafe, and it is easy to accidentally violate the invariants (even if it seems obvious at first).
    /// For that reason, the below function aims to explicitly bring the safety invariants to notice
    /// so we don't accidentally make that mistake. It also lets you convert a string to utf-16,
    /// so it's also convenient in that sense.
    ///
    /// SAFETY:
    /// - You must bind PCWSTRWrapper to a variable, or it'll create a temporary and drop it.
    ///   E.g. `let foo = "bar".to_pcwstr().as_pcwstr()` drops after statement, and
    ///        the raw pointer is dangling
    ///   However, `foo("bar".to_pcwstr().as_pcwstr())` is fine since it'll drop after
    ///   the fn call
    /// - Since this hands out a raw pointer, it can easily escape the lifetime of PCWSTRWrapper.
    ///   Ensure you or the function you called does not use the PCWSTR after PCWSTRWrapper gets dropped
    pub unsafe fn as_pcwstr(&self) -> PCWSTR {
        PCWSTR::from_raw(self.0.as_ptr())
    }

    fn new<T: AsRef<str>>(text: T) -> Self {
        let text = text.as_ref();
        // do not drop when scope ends, by moving it into struct
        let mut text = text.encode_utf16().collect::<Vec<_>>();
        text.push(0);

        Self(text)
    }
}

pub(crate) trait ToPCWSTRWrapper {
    fn to_pcwstr(&self) -> PCWSTRWrapper;
}

impl ToPCWSTRWrapper for &str {
    fn to_pcwstr(&self) -> PCWSTRWrapper {
        PCWSTRWrapper::new(self)
    }
}

impl ToPCWSTRWrapper for String {
    fn to_pcwstr(&self) -> PCWSTRWrapper {
        PCWSTRWrapper::new(self)
    }
}
