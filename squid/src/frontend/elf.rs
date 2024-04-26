use std::path::{
    Path,
    PathBuf,
};

use goblin;
use memmap2::{
    Mmap,
    MmapOptions,
};
use paste::paste;

use crate::{
    event::EventPool,
    frontend::{
        error::LoaderError,
        idmap::{
            idmap_functions,
            HasId,
            HasIdMut,
            Id,
            IdMap,
            IdMapValues,
            IdMapValuesMut,
        },
        image::VAddr,
        section::{
            Section,
            SectionParser,
        },
        tls::{
            Tls,
            TlsParser,
        },
    },
    listing::ListingManager,
    logger::Logger,
};

#[derive(Debug)]
pub struct Elf {
    id: Id,
    path: PathBuf,
    tls: Tls,
    idmap: IdMap<Section>,
    cursor: usize,
}

impl Elf {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn tls(&self) -> &Tls {
        &self.tls
    }

    pub fn tls_mut(&mut self) -> &mut Tls {
        &mut self.tls
    }

    pub fn builder() -> ElfBuilder {
        ElfBuilder {
            path: None,
        }
    }
}

idmap_functions!(Elf, Section, section);

impl HasId for Elf {
    fn id(&self) -> Id {
        self.id
    }
}

impl HasIdMut for Elf {
    fn id_mut(&mut self) -> &mut Id {
        &mut self.id
    }
}

pub struct ElfBuilder {
    path: Option<PathBuf>,
}

impl ElfBuilder {
    pub fn path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn build(self) -> Result<Elf, &'static str> {
        let path = self.path.ok_or("Elf path was not set")?;
        Ok(Elf {
            id: Id::default(),
            path,
            tls: Tls::new(),
            idmap: IdMap::new(),
            cursor: 0,
        })
    }
}

fn mmap_file(path: &Path) -> std::io::Result<Mmap> {
    let file = std::fs::File::open(path)?;
    let map = unsafe { MmapOptions::new().map(&file) }?;
    Ok(map)
}

fn get_dependencies(elf: &goblin::elf::Elf) -> Vec<String> {
    let mut ret = Vec::<String>::new();

    if let Some(dynamic) = &elf.dynamic {
        for entry in &dynamic.dyns {
            if entry.d_tag == goblin::elf::dynamic::DT_NEEDED {
                let dep = elf.dynstrtab.get_at(entry.d_val as usize).unwrap();

                if ret.iter().all(|x| x.as_str() != dep) {
                    ret.push(dep.to_string());
                }
            }
        }
    }

    ret
}

fn verify_elf(elf: &goblin::elf::Elf) -> bool {
    elf.is_64 && elf.little_endian && elf.header.e_type == goblin::elf::header::ET_DYN && elf.header.e_machine == goblin::elf::header::EM_RISCV
}

#[derive(Clone, Debug)]
pub(crate) struct PointerArray {
    pub(crate) vaddr: VAddr,
    pub(crate) entries: usize,
}

fn get_preinit_array(elf: &goblin::elf::Elf) -> Option<PointerArray> {
    let mut vaddr = None;
    let mut size = None;

    if let Some(dynamic) = &elf.dynamic {
        for entry in &dynamic.dyns {
            match entry.d_tag {
                goblin::elf::dynamic::DT_PREINIT_ARRAY => vaddr = Some(entry.d_val as VAddr),
                goblin::elf::dynamic::DT_PREINIT_ARRAYSZ => size = Some(entry.d_val as usize),
                _ => {},
            }
        }
    }

    match (vaddr, size) {
        (Some(vaddr), Some(size)) => {
            assert!(size % 8 == 0);

            Some(PointerArray {
                vaddr,
                entries: size / 8,
            })
        },
        _ => None,
    }
}

fn get_init_array(elf: &goblin::elf::Elf) -> Option<PointerArray> {
    let mut vaddr = None;
    let mut size = None;

    if let Some(dynamic) = &elf.dynamic {
        for entry in &dynamic.dyns {
            match entry.d_tag {
                goblin::elf::dynamic::DT_INIT_ARRAY => vaddr = Some(entry.d_val as VAddr),
                goblin::elf::dynamic::DT_INIT_ARRAYSZ => size = Some(entry.d_val as usize),
                _ => {},
            }
        }
    }

    match (vaddr, size) {
        (Some(vaddr), Some(size)) => {
            assert!(size % 8 == 0);

            Some(PointerArray {
                vaddr,
                entries: size / 8,
            })
        },
        _ => None,
    }
}

fn get_init(elf: &goblin::elf::Elf) -> Option<VAddr> {
    let mut ret = None;

    if let Some(dynamic) = &elf.dynamic {
        for entry in &dynamic.dyns {
            if entry.d_tag == goblin::elf::dynamic::DT_INIT {
                ret = Some(entry.d_val as VAddr);
            }
        }
    }

    ret
}

pub(crate) struct ElfParser {
    dependencies: Vec<String>,
    entrypoint: VAddr,
    preinit_array: Option<PointerArray>,
    init_array: Option<PointerArray>,
    init: Option<VAddr>,
}

impl ElfParser {
    pub(crate) fn new() -> Self {
        Self {
            dependencies: Vec::new(),
            entrypoint: 0,
            preinit_array: None,
            init_array: None,
            init: None,
        }
    }

    pub(crate) fn parse(&mut self, path: &Path, event_pool: &mut EventPool, logger: &Logger) -> Result<Elf, LoaderError> {
        let file = mmap_file(path).map_err(|_| LoaderError::IOError(format!("Cannot read from {}", path.display())))?;
        let elf = goblin::elf::Elf::parse(&file).unwrap();

        if !verify_elf(&elf) {
            return Err(LoaderError::InvalidELF("Not a 64-bit little-endian RISC-V PIE/DSO".to_string()));
        }

        self.dependencies = get_dependencies(&elf);
        self.preinit_array = get_preinit_array(&elf);
        self.init_array = get_init_array(&elf);
        self.init = get_init(&elf);
        self.entrypoint = elf.entry as VAddr;

        let listing = ListingManager::new(path);

        if listing.have_metadata() {
            logger.info("  -> Using metadata file");
        } else {
            logger.info("  -> No metadata");
        }

        let sections = SectionParser::parse(&elf, &file[..], &listing, event_pool)?;
        let tls = TlsParser::parse(&elf, &file[..])?;

        Ok(Elf {
            path: path.to_path_buf(),
            id: Id::default(),
            idmap: sections,
            tls,
            cursor: 0,
        })
    }

    pub(crate) fn dependencies(&self) -> &[String] {
        &self.dependencies
    }

    pub(crate) fn entrypoint(&self) -> VAddr {
        self.entrypoint
    }

    pub(crate) fn preinit_array(&self) -> Option<&PointerArray> {
        self.preinit_array.as_ref()
    }

    pub(crate) fn init_array(&self) -> Option<&PointerArray> {
        self.init_array.as_ref()
    }

    pub(crate) fn init(&self) -> Option<&VAddr> {
        self.init.as_ref()
    }
}
