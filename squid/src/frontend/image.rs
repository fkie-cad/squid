use std::path::Path;

use paste::paste;

use crate::{
    event::EventPool,
    frontend::{
        chunk::ChunkContent,
        dependency::DependencyGraph,
        elf::{
            Elf,
            ElfParser,
            PointerArray,
        },
        error::LoaderError,
        idmap::{
            idmap_functions,
            HasId,
            Id,
            IdMap,
            IdMapValues,
            IdMapValuesMut,
        },
        pointer::{
            BasicBlockPointer,
            FunctionPointer,
            GlobalPointer,
            Pointer,
            ThreadLocalPointer,
        },
        reloc::Relocation,
        symbolization_passes::{
            AddressPropagationPass,
            DeadCodeEliminationPass,
            EliminateArithmeticPass,
            EliminateEmptyBasicBlocksPass,
            HandleRelaxationPass,
            MetadataPass,
            RegisterCachingPass,
            SymbolizerPass,
        },
    },
    logger::Logger,
};

/// An address that points somewhere into the virtual address space of the target application
pub type VAddr = u64;

/// The ProcessImage contains all necessary ELF files for emulation
///
/// It
/// - parses its binaries into a tree structure instead of a linear memory image
/// - symbolizes all pointers in the ELF files
/// - lifts all RISC-V instructions into an IR
#[derive(Debug, Hash)]
pub struct ProcessImage {
    idmap: IdMap<Elf>,
    cursor: usize,
    entrypoint: FunctionPointer,
    constructors: Vec<FunctionPointer>,
}

idmap_functions!(ProcessImage, Elf, elf);

impl ProcessImage {
    /// The entrypoint of the ProcessImage determines where to start execution
    pub fn entrypoint(&self) -> &FunctionPointer {
        &self.entrypoint
    }

    /// Change the entrypoint of this ProcessImage
    pub fn set_entrypoint(&mut self, entrypoint: FunctionPointer) {
        self.entrypoint = entrypoint;
    }

    /// The constructors that are to be run before the entrypoint in the order given by this slice
    pub fn constructors(&self) -> &[FunctionPointer] {
        &self.constructors
    }

    /// Change the constructors of this ProcessImage
    pub fn constructors_mut(&mut self) -> &mut Vec<FunctionPointer> {
        &mut self.constructors
    }

    /// Get an ELF file by its filename
    pub fn elf_by_filename<S: AsRef<str>>(&self, filename: S) -> Option<&Elf> {
        let filename = filename.as_ref();

        for elf in self.iter_elfs() {
            if let Some(elf_name) = elf.path().file_name().and_then(|x| x.to_str()) {
                if elf_name == filename {
                    return Some(elf);
                }
            }
        }

        None
    }

    /// Get an ELF file by its filename
    pub fn elf_by_filename_mut<S: AsRef<str>>(&mut self, filename: S) -> Option<&mut Elf> {
        let filename = filename.as_ref();

        for elf in self.iter_elfs_mut() {
            if let Some(elf_name) = elf.path().file_name().and_then(|x| x.to_str()) {
                if elf_name == filename {
                    return Some(elf);
                }
            }
        }

        None
    }
}

enum Constructor {
    Function(usize, VAddr),
    Array(usize, PointerArray),
}

fn is_optional_import(name: &str) -> bool {
    matches!(name, "_ITM_deregisterTMCloneTable" | "_ITM_registerTMCloneTable")
}

pub(crate) struct ProcessImageBuilder {
    elfs: Vec<Elf>,
    graph: DependencyGraph,
    map: IdMap<Elf>,
    entrypoint: Option<VAddr>,
    constructors: Vec<Constructor>,
}

impl ProcessImageBuilder {
    pub(crate) fn build<S>(binary: S, search_paths: &[S], preloads: &[S], event_pool: &mut EventPool, logger: &Logger) -> Result<ProcessImage, LoaderError>
    where
        S: AsRef<Path>,
    {
        let mut builder = Self::new();
        builder.lift_elfs(binary, search_paths, preloads, event_pool, logger)?;
        builder.log_functions(logger);
        builder.resolve_symbols(logger)?;
        builder.symbolize(logger)?;
        let entrypoint = builder.symbolize_entrypoint()?;
        let constructors = builder.symbolize_constructors()?;

        /* Build IdMap */
        let mut map = builder.map;

        for elf in builder.elfs {
            map.insert(elf);
        }

        logger.info("Symbolic loading successful");

        Ok(ProcessImage {
            idmap: map,
            cursor: 0,
            entrypoint,
            constructors,
        })
    }

    fn new() -> Self {
        Self {
            elfs: Vec::new(),
            graph: DependencyGraph::new(),
            map: IdMap::new(),
            entrypoint: None,
            constructors: Vec::new(),
        }
    }

    fn find_code_pointer(&self, elf: usize, vaddr: VAddr) -> Result<Option<FunctionPointer>, LoaderError> {
        let mut definition = None;

        for section in self.elfs[elf].iter_sections() {
            if !section.contains_address(vaddr) {
                continue;
            }

            for symbol in section.iter_symbols() {
                if !symbol.contains_address(vaddr) {
                    continue;
                }

                for chunk in symbol.iter_chunks() {
                    if chunk.vaddr() != vaddr || chunk.pending().is_some() {
                        continue;
                    }

                    if let ChunkContent::Pointer(pointer) = chunk.content() {
                        match pointer {
                            Pointer::Function(pointer) => {
                                definition = Some(pointer.clone());
                            },
                            _ => {
                                return Err(LoaderError::LoadingError(format!("Constructor is not a function: {:?}", pointer)));
                            },
                        }
                    }
                }
            }
        }

        Ok(definition)
    }

    fn symbolize_constructors(&self) -> Result<Vec<FunctionPointer>, LoaderError> {
        let mut ret = Vec::new();

        for ctor in &self.constructors {
            match ctor {
                Constructor::Function(elf, addr) => {
                    let pointer = self.find_function(*elf, *addr)?;
                    let pointer = pointer.ok_or_else(|| LoaderError::LoadingError(format!("Could not find constructor {:#x} in process image", addr)))?;
                    ret.push(pointer);
                },
                Constructor::Array(elf, array) => {
                    for i in 0..array.entries {
                        let addr = array.vaddr + i as VAddr * 8;
                        let pointer = self.find_code_pointer(*elf, addr)?;
                        let pointer = pointer.ok_or_else(|| LoaderError::LoadingError(format!("Could not find constructor function {:#x} in process image", addr)))?;
                        ret.push(pointer);
                    }
                },
            }
        }

        Ok(ret)
    }

    fn find_function(&self, elf: usize, vaddr: VAddr) -> Result<Option<FunctionPointer>, LoaderError> {
        let mut definition = None;

        for section in self.elfs[elf].iter_sections() {
            if !section.contains_address(vaddr) {
                continue;
            }

            for symbol in section.iter_symbols() {
                if !symbol.contains_address(vaddr) {
                    continue;
                }

                for chunk in symbol.iter_chunks() {
                    if !chunk.contains_address(vaddr) {
                        continue;
                    }

                    if chunk.pending().is_none() {
                        if let ChunkContent::Code(func) = chunk.content() {
                            let entry = func.cfg().entry();

                            if func.cfg().basic_block(entry).unwrap().vaddr() == Some(vaddr) {
                                if definition.is_some() {
                                    return Err(LoaderError::LoadingError(format!("Multiple occurences of function {:#x}", vaddr)));
                                }

                                definition = Some(FunctionPointer {
                                    elf: self.elfs[elf].id(),
                                    section: section.id(),
                                    symbol: symbol.id(),
                                    chunk: chunk.id(),
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(definition)
    }

    fn symbolize_entrypoint(&self) -> Result<FunctionPointer, LoaderError> {
        let entrypoint = self.entrypoint.ok_or_else(|| LoaderError::InvalidELF("Could not find an entrypoint".to_string()))?;
        let sym_entrypoint = self.find_function(0, entrypoint)?;
        sym_entrypoint.ok_or_else(|| LoaderError::LoadingError(format!("Could not find entrypoint {:#x} in process image", entrypoint)))
    }

    fn symbolize(&mut self, logger: &Logger) -> Result<(), LoaderError> {
        for elf in &mut self.elfs {
            logger.info(format!("Symbolizing {}", elf.path().file_name().unwrap().to_str().unwrap()));

            /* First preprocess the code for symbolization using various passes */
            for section in elf.iter_sections_mut() {
                if !section.perms().is_executable() {
                    continue;
                }

                for symbol in section.iter_symbols_mut() {
                    for chunk in symbol.iter_chunks_mut() {
                        if let ChunkContent::Code(func) = chunk.content_mut() {
                            let mut pass = RegisterCachingPass::new();
                            if let Err(err) = pass.run(func) {
                                return Err(LoaderError::CodeSymbolizationError(err));
                            }

                            let mut pass = EliminateArithmeticPass::new();
                            if let Err(err) = pass.run(func) {
                                return Err(LoaderError::CodeSymbolizationError(err));
                            }

                            let mut pass = DeadCodeEliminationPass::new();
                            if let Err(err) = pass.run(func) {
                                return Err(LoaderError::CodeSymbolizationError(err));
                            }

                            let mut pass = AddressPropagationPass::new();
                            if let Err(err) = pass.run(func) {
                                return Err(LoaderError::CodeSymbolizationError(err));
                            }

                            let pass = MetadataPass::new();
                            if let Err(err) = pass.run(func) {
                                return Err(LoaderError::CodeSymbolizationError(err));
                            }

                            let mut pass = EliminateEmptyBasicBlocksPass::new();
                            if let Err(err) = pass.run(func) {
                                return Err(LoaderError::CodeSymbolizationError(err));
                            }
                        }
                    }
                }
            }

            /* Handle code relaxations by the compiler */
            let mut pass = HandleRelaxationPass::new();
            if let Err(err) = pass.run(elf) {
                return Err(LoaderError::CodeSymbolizationError(err));
            }

            /* Then symbolize code and data */
            let mut pass = SymbolizerPass::new();
            if let Err(err) = pass.run(elf) {
                return Err(LoaderError::CodeSymbolizationError(err));
            }
        }

        Ok(())
    }

    fn find_symbol_export(&self, elf: usize, name: &str) -> Result<Option<Pointer>, LoaderError> {
        let mut definition = None;
        let elf_id = self.elfs[elf].id();
        assert_ne!(elf_id, Id::default());

        for section in self.elfs[elf].iter_sections() {
            for symbol in section.iter_symbols() {
                if let Some(symbol_addr) = symbol.public_name(name) {
                    for chunk in symbol.iter_chunks() {
                        if chunk.contains_address(symbol_addr) {
                            if chunk.pending().is_some() || matches!(chunk.content(), ChunkContent::Data { .. } | ChunkContent::Pointer(_)) {
                                if definition.is_some() {
                                    return Err(LoaderError::SymbolResolutionError(format!("{} has multiple exports of {}", self.elfs[elf].path().display(), name)));
                                }

                                definition = Some(Pointer::Global(GlobalPointer {
                                    elf: elf_id,
                                    section: section.id(),
                                    symbol: symbol.id(),
                                    chunk: chunk.id(),
                                    offset: (symbol_addr - chunk.vaddr()) as usize,
                                }));
                            } else {
                                let ChunkContent::Code(func) = chunk.content() else { unreachable!() };

                                for bb in func.cfg().iter_basic_blocks() {
                                    if bb.vaddr() == Some(symbol_addr) {
                                        if definition.is_some() {
                                            return Err(LoaderError::SymbolResolutionError(format!("{} has multiple exports of {}", self.elfs[elf].path().display(), name)));
                                        }

                                        if bb.id() == func.cfg().entry() {
                                            definition = Some(Pointer::Function(FunctionPointer {
                                                elf: elf_id,
                                                section: section.id(),
                                                symbol: symbol.id(),
                                                chunk: chunk.id(),
                                            }));
                                        } else {
                                            definition = Some(Pointer::BasicBlock(BasicBlockPointer {
                                                elf: elf_id,
                                                section: section.id(),
                                                symbol: symbol.id(),
                                                chunk: chunk.id(),
                                                bb: bb.id(),
                                            }));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(definition)
    }

    fn resolve_global_symbols(&mut self, logger: &Logger) -> Result<(), LoaderError> {
        for i in 0..self.elfs.len() {
            let walk = self.graph.walk(i);
            let mut imports = Vec::<(String, Id, Id, Id)>::new();

            /* First find all symbol imports for the current ELF file */
            for section in self.elfs[i].iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if let Some(Relocation::SymbolImport(name)) = chunk.pending() {
                            imports.push((name.clone(), section.id(), symbol.id(), chunk.id()));
                        }
                    }
                }
            }

            /* For each symbol find out which dependency defines it */
            for (name, src_section, src_symbol, src_chunk) in imports {
                let mut definition = None;

                for &dep in &walk {
                    definition = self.find_symbol_export(dep, &name)?;

                    if definition.is_some() {
                        break;
                    }
                }

                let pointer = if let Some(pointer) = definition {
                    pointer
                } else if is_optional_import(&name) {
                    logger.warning(format!("Ignoring unresolved symbol '{}' from {}", name, self.elfs[i].path().display()));
                    Pointer::Null
                } else {
                    let msg = format!("Unable to resolve '{}' from {}", name, self.elfs[i].path().display());
                    logger.error(&msg);
                    return Err(LoaderError::SymbolResolutionError(msg));
                };

                self.elfs[i].section_mut(src_section).unwrap().symbol_mut(src_symbol).unwrap().chunk_mut(src_chunk).unwrap().resolve(pointer);
            }
        }

        Ok(())
    }

    fn resolve_local_symbols(&mut self, logger: &Logger) -> Result<(), LoaderError> {
        for i in 0..self.elfs.len() {
            let walk = self.graph.walk(i);
            let mut imports = Vec::<(String, Id, Id, Id)>::new();

            /* First find all symbol imports for the current ELF file */
            for section in self.elfs[i].iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if let Some(Relocation::TlsSymbolImport(name)) = chunk.pending() {
                            imports.push((name.clone(), section.id(), symbol.id(), chunk.id()));
                        }
                    }
                }
            }

            /* For each symbol find out which dependency defines it */
            for (name, src_section, src_symbol, src_chunk) in imports {
                let mut definition = None;

                for &dep in &walk {
                    let elf_id = self.elfs[dep].id();
                    assert_ne!(elf_id, Id::default());

                    for thread_local in self.elfs[dep].tls().iter_thread_locals() {
                        if thread_local.public_names().contains(&name) {
                            if definition.is_some() {
                                return Err(LoaderError::SymbolResolutionError(format!("{} has multiple exports of {}", self.elfs[dep].path().display(), name)));
                            }

                            definition = Some(ThreadLocalPointer {
                                elf: elf_id,
                                local: thread_local.id(),
                                offset: 0,
                            });
                        }
                    }

                    if definition.is_some() {
                        break;
                    }
                }

                let pointer = if let Some(pointer) = definition {
                    Pointer::Local(pointer)
                } else if is_optional_import(&name) {
                    logger.warning(format!("Ignoring unresolved symbol '{}' from {}", name, self.elfs[i].path().display()));
                    Pointer::Null
                } else {
                    let msg = format!("Unable to resolve '{}' from {}", name, self.elfs[i].path().display());
                    logger.error(&msg);
                    return Err(LoaderError::SymbolResolutionError(msg));
                };

                self.elfs[i].section_mut(src_section).unwrap().symbol_mut(src_symbol).unwrap().chunk_mut(src_chunk).unwrap().resolve(pointer);
            }
        }

        Ok(())
    }

    fn resolve_symbols(&mut self, logger: &Logger) -> Result<(), LoaderError> {
        logger.info("Resolving symbol imports");
        self.resolve_global_symbols(logger)?;
        self.resolve_local_symbols(logger)?;
        Ok(())
    }

    fn log_functions(&self, logger: &Logger) {
        let mut perfect = 0;
        let mut total = 0;

        for elf in &self.elfs {
            for section in elf.iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if chunk.pending().is_some() {
                            continue;
                        }

                        if let ChunkContent::Code(func) = chunk.content() {
                            if func.perfect() {
                                perfect += 1;
                            } else {
                                logger.debug(format!("Function at {:#x} from {} has imperfect CFG", chunk.vaddr(), elf.path().display()));
                            }

                            total += 1;
                        }
                    }
                }
            }
        }

        logger.info(format!("{} / {} functions have perfect CFG", perfect, total));
    }

    fn lift_elfs<S>(&mut self, binary: S, search_paths: &[S], preloads: &[S], event_pool: &mut EventPool, logger: &Logger) -> Result<(), LoaderError>
    where
        S: AsRef<Path>,
    {
        let mut constructors = Vec::new();
        let root = self.graph.add_node(binary);

        for dso in preloads {
            let node = self.graph.add_node(dso);
            self.graph.add_edge(root, node);
        }

        while let Some((node, path)) = self.graph.next_unvisited() {
            logger.info(format!("Lifting {}", path.display()));

            let mut parser = ElfParser::new();
            let mut elf = parser.parse(path, event_pool, logger)?;
            let idx = self.elfs.len();
            self.map.reserve_id(&mut elf);

            if self.entrypoint.is_none() {
                self.entrypoint = Some(parser.entrypoint());

                if let Some(preinit_array) = parser.preinit_array() {
                    self.constructors.push(Constructor::Array(idx, preinit_array.clone()));
                }
            }

            if let Some(init_array) = parser.init_array() {
                constructors.insert(0, Constructor::Array(idx, init_array.clone()));
            }

            if let Some(init) = parser.init() {
                constructors.insert(0, Constructor::Function(idx, *init));
            }

            for dep in parser.dependencies() {
                let mut path = None;

                for search_path in search_paths {
                    let resolved_path = search_path.as_ref().join(dep);

                    if resolved_path.exists() {
                        path = Some(resolved_path);
                        break;
                    }
                }

                if let Some(path) = path {
                    let target = self.graph.add_node(path);
                    self.graph.add_edge(node, target);
                } else {
                    return Err(LoaderError::DependencyNotFound(dep.clone()));
                }
            }

            self.elfs.push(elf);
        }

        self.constructors.append(&mut constructors);

        Ok(())
    }
}
