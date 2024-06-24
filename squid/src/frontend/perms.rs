use goblin;

const PERM_X: u8 = 1;
const PERM_W: u8 = 2;
const PERM_R: u8 = 4;

/// The permissions memory and elements in the process image can have
#[derive(Copy, Clone, PartialEq, Debug, Default, Hash)]
pub struct Perms(u8);

impl Perms {
    pub(crate) fn from_segment_flags(flags: u32) -> Self {
        let mut perms = Perms(0);

        if (flags & goblin::elf::program_header::PF_X) != 0 {
            perms.make_executable();
        }

        if (flags & goblin::elf::program_header::PF_W) != 0 {
            perms.make_writable();
        }

        if (flags & goblin::elf::program_header::PF_R) != 0 {
            perms.make_readable();
        }

        perms
    }

    pub(crate) fn from_section_header(header: &goblin::elf::section_header::SectionHeader) -> Self {
        let mut perms = Perms(0);
        perms.make_readable();

        if header.is_executable() {
            perms.make_executable();
        }

        if header.is_writable() {
            perms.make_writable();
        }

        perms
    }

    #[allow(missing_docs)]
    pub fn is_executable(&self) -> bool {
        (self.0 & PERM_X) != 0
    }

    #[allow(missing_docs)]
    pub fn is_writable(&self) -> bool {
        (self.0 & PERM_W) != 0
    }

    #[allow(missing_docs)]
    pub fn is_readable(&self) -> bool {
        (self.0 & PERM_R) != 0
    }

    #[allow(missing_docs)]
    pub fn is_inaccessible(&self) -> bool {
        self.0 == 0
    }

    #[allow(missing_docs)]
    pub fn clear_executable(&mut self) {
        self.0 &= !PERM_X;
    }

    #[allow(missing_docs)]
    pub fn clear_writable(&mut self) {
        self.0 &= !PERM_W;
    }

    #[allow(missing_docs)]
    pub fn clear_readable(&mut self) {
        self.0 &= !PERM_R;
    }

    #[allow(missing_docs)]
    pub fn make_executable(&mut self) {
        self.0 |= PERM_X
    }

    #[allow(missing_docs)]
    pub fn make_readable(&mut self) {
        self.0 |= PERM_R
    }

    #[allow(missing_docs)]
    pub fn make_writable(&mut self) {
        self.0 |= PERM_W
    }
}
