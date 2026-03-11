use std::{
    fmt::Display,
    ops::{BitOr, BitOrAssign},
};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CapabilityFlags(u32);
impl CapabilityFlags {
    pub const DELEGATE: Self = Self(0x1);
    pub const MUTUAL_AUTH: Self = Self(0x02);
    pub const CONFIDENTIALITY: Self = Self(0x10);
    pub const INTEGRITY: Self = Self(0x20000);
    pub const fn contains_all(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn add_flag(&mut self, flag: Self) {
        *self |= flag
    }
    pub fn remove_flag(&mut self, flag: Self) {
        *self = Self(self.0 & !flag.0)
    }
    pub fn as_u32(self) -> u32 {
        self.0
    }
}
impl Display for CapabilityFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut strings: Vec<&'static str> = vec![];
        if self.contains_all(Self::DELEGATE) {
            strings.push("DELEGATE");
        }
        if self.contains_all(Self::MUTUAL_AUTH) {
            strings.push("MUTUAL_AUTH");
        }
        if self.contains_all(Self::INTEGRITY) {
            strings.push("INTEGRITY");
        }
        if self.contains_all(Self::CONFIDENTIALITY) {
            strings.push("CONFIDENTIALITY");
        }
        write!(f, "{}", strings.join(" | "))
    }
}
impl BitOr for CapabilityFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}
impl BitOrAssign for CapabilityFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs
    }
}
