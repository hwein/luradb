//! `page` module
//!
//! This module defines the on-disk structure of a Page, the basic storage unit.
//! All data is stored in pages of a fixed size (`PAGE_SIZE`). A page is composed
//! of a header containing metadata and a data area.

use std::fmt;

// --- Constants ---

/// The size of a single page in bytes (e.g., 4KB).
pub const PAGE_SIZE: usize = 4096;

// --- PageId ---

/// A unique identifier for a page in the database file.
/// It corresponds to the page's offset in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct PageId(pub u64);

impl From<u64> for PageId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl fmt::Display for PageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PageId({})", self.0)
    }
}

// --- Page Header ---

/// The header of a page, containing metadata.
/// The `repr(C)` attribute is crucial to ensure a consistent memory layout,
/// allowing the struct to be safely cast to and from a byte array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct PageHeader {
    /// The ID of this page. Should match the page's offset in the file.
    pub page_id: PageId,
    /// Log Sequence Number for recovery purposes.
    pub lsn: u64,
    /// A checksum to verify page integrity on disk.
    pub checksum: u64,
    /// Reserved space for future metadata fields.
    _reserved: u64,
}

impl PageHeader {
    /// The size of the `PageHeader` in bytes.
    pub const SIZE: usize = std::mem::size_of::<Self>();
}

// --- Page ---

/// The size of the usable data area within a page.
pub const PAGE_DATA_SIZE: usize = PAGE_SIZE - PageHeader::SIZE;

/// Represents a single, fixed-size page as it is stored on disk and in memory.
/// `repr(C)` ensures that the layout of the struct in memory is the same as
/// its C representation, which is essential for safe casting to a byte array.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct Page {
    pub header: PageHeader,
    pub data: [u8; PAGE_DATA_SIZE],
}

// Static assertion to guarantee that the Page struct has the correct total size.
// This is a critical safety check for the unsafe casting later.
const_assert_eq!(std::mem::size_of::<Page>(), PAGE_SIZE);

impl Default for Page {
    fn default() -> Self {
        Self {
            header: PageHeader {
                page_id: PageId(0), // A default/invalid page ID
                lsn: 0,
                checksum: 0,
                _reserved: 0,
            },
            data: [0; PAGE_DATA_SIZE],
        }
    }
}

impl Page {
    /// Returns the entire page as an immutable byte slice for I/O.
    ///
    /// # Safety
    /// This is safe because the struct has `#[repr(C)]` and its size is
    /// statically asserted to be `PAGE_SIZE`.
    pub fn as_bytes(&self) -> &[u8; PAGE_SIZE] {
        unsafe { &*(self as *const Self as *const [u8; PAGE_SIZE]) }
    }

    /// Returns the entire page as a mutable byte slice for I/O.
    ///
    /// # Safety
    /// This is safe for the same reasons as `as_bytes`.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; PAGE_SIZE] {
        unsafe { &mut *(self as *mut Self as *mut [u8; PAGE_SIZE]) }
    }

    /// Returns a mutable slice to the data portion of the page.
    pub fn data_mut(&mut self) -> &mut [u8; PAGE_DATA_SIZE] {
        &mut self.data
    }

    /// Returns an immutable slice of the data portion of the page.
    pub fn data(&self) -> &[u8; PAGE_DATA_SIZE] {
        &self.data
    }

    // A simple checksum calculation.
    // In a real database, a more robust algorithm like CRC32C would be used.
    pub fn calculate_checksum(&self) -> u64 {
        let mut sum = self.header.page_id.0 + self.header.lsn;
        for &byte in self.data.iter() {
            sum = sum.wrapping_add(byte as u64);
        }
        sum
    }

    /// Updates the checksum in the header.
    pub fn update_checksum(&mut self) {
        self.header.checksum = self.calculate_checksum();
    }

    /// Verifies that the stored checksum matches the calculated one.
    pub fn verify_checksum(&self) -> bool {
        self.header.checksum == self.calculate_checksum()
    }
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page")
            .field("header", &self.header)
            // Do not print the entire data array to avoid spamming logs.
            .field("data", &"...")
            .finish()
    }
}

// Helper for static assertions. Requires the `static_assertions` crate
// or can be implemented manually like this.
macro_rules! const_assert_eq {
    ($left:expr, $right:expr) => {
        const _: [(); $left] = [(); $right];
    };
}
use const_assert_eq;