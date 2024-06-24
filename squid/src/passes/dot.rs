use std::{
    fs::File,
    io::Write,
    path::PathBuf,
};

use crate::{
    event::EventPool,
    frontend::{
        ao::{
            Edge,
            Function,
        },
        ChunkContent,
        HasId,
        Pointer,
        ProcessImage,
        VAddr,
    },
    logger::Logger,
    passes::Pass,
};

/// ImageDOTPass dumps the process image as a .dot file
pub struct ImageDOTPass {
    filename: PathBuf,
}

impl ImageDOTPass {
    /// Create a new ImageDOTPass
    pub fn new<S: Into<PathBuf>>(filename: S) -> Self {
        Self {
            filename: filename.into(),
        }
    }

    fn create_dot(&self, image: &ProcessImage) -> std::io::Result<()> {
        let mut output = File::create(&self.filename)?;

        writeln!(&mut output, "digraph ProcessImage {{")?;
        writeln!(&mut output, "graph [center=true];")?;
        writeln!(&mut output, "node [shape=rectangle, style=filled, fillcolor=cornsilk, fontcolor=black, ordering=out];")?;
        writeln!(&mut output, "root [shape=point, id=\"root\"];")?;

        for elf in image.iter_elfs() {
            writeln!(&mut output, "elf_{} [label=\"[{}] {}\"];", elf.id(), elf.id(), elf.path().file_name().unwrap().to_str().unwrap())?;
            writeln!(&mut output, "root -> elf_{};", elf.id())?;

            for section in elf.iter_sections() {
                writeln!(
                    &mut output,
                    "elf_{}_section_{} [label=\"[{}] {}{}{}\"];",
                    elf.id(),
                    section.id(),
                    section.id(),
                    if section.perms().is_readable() { "r" } else { "-" },
                    if section.perms().is_writable() { "w" } else { "-" },
                    if section.perms().is_executable() { "x" } else { "-" },
                )?;
                writeln!(&mut output, "elf_{} -> elf_{}_section_{};", elf.id(), elf.id(), section.id())?;

                for symbol in section.iter_symbols() {
                    write!(&mut output, "elf_{}_section_{}_symbol_{} [label=\"[{}]\\n", elf.id(), section.id(), symbol.id(), symbol.id())?;

                    for public_name in symbol.public_names() {
                        write!(&mut output, "{}\\n", public_name)?;
                    }

                    if symbol.public_names().count() > 0 && symbol.private_names().count() > 0 {
                        write!(&mut output, "-----\\n")?;
                    }

                    for private_name in symbol.private_names() {
                        write!(&mut output, "{}\\n", private_name)?;
                    }

                    writeln!(&mut output, "\"];")?;

                    writeln!(&mut output, "elf_{}_section_{} -> elf_{}_section_{}_symbol_{};", elf.id(), section.id(), elf.id(), section.id(), symbol.id())?;

                    for chunk in symbol.iter_chunks() {
                        writeln!(
                            &mut output,
                            "elf_{}_section_{}_symbol_{}_chunk_{} [shape=rect, label=\"[{}] {:#x} - {:#x}:\\n{}\"];",
                            elf.id(),
                            section.id(),
                            symbol.id(),
                            chunk.id(),
                            chunk.id(),
                            chunk.vaddr(),
                            chunk.last_addr() + 1,
                            if chunk.pending().is_some() {
                                "rel".to_string()
                            } else {
                                match chunk.content() {
                                    ChunkContent::Code(_) => "code".to_string(),
                                    ChunkContent::Data {
                                        ..
                                    } => "data".to_string(),
                                    ChunkContent::Pointer(pointer) => match pointer {
                                        Pointer::Global(pointer) => format!("{:?}", pointer),
                                        Pointer::Local(pointer) => format!("{:?}", pointer),
                                        Pointer::Function(pointer) => format!("{:?}", pointer),
                                        Pointer::BasicBlock(pointer) => format!("{:?}", pointer),
                                        pointer => format!("{:?}", pointer),
                                    },
                                }
                            }
                        )?;
                        writeln!(
                            &mut output,
                            "elf_{}_section_{}_symbol_{} -> elf_{}_section_{}_symbol_{}_chunk_{};",
                            elf.id(),
                            section.id(),
                            symbol.id(),
                            elf.id(),
                            section.id(),
                            symbol.id(),
                            chunk.id()
                        )?;
                    }
                }
            }
        }

        writeln!(&mut output, "}}")?;
        output.flush()?;
        Ok(())
    }
}

impl Pass for ImageDOTPass {
    type Error = std::io::Error;

    fn name(&self) -> String {
        "ImageDOTPass".to_string()
    }

    fn run(&mut self, image: &mut ProcessImage, _event_pool: &mut EventPool, _logger: &Logger) -> Result<(), Self::Error> {
        self.create_dot(image)
    }
}

/// The FunctionDOTPass dumps the CFG of selected functions into a .dot file
pub struct FunctionDOTPass {
    filename: PathBuf,
    private_name: Option<String>,
    public_name: Option<String>,
    addr: Option<VAddr>,
}

impl FunctionDOTPass {
    /// Create a new FunctionDOTPass
    #[allow(clippy::new_without_default)]
    pub fn new<P: Into<PathBuf>>(filename: P) -> Self {
        Self {
            filename: filename.into(),
            private_name: None,
            public_name: None,
            addr: None,
        }
    }

    /// Dump functions with the given private name
    pub fn private_name<S: Into<String>>(&mut self, name: S) -> &mut Self {
        self.private_name = Some(name.into());
        self
    }

    /// Dump functions with the given public name
    pub fn public_name<S: Into<String>>(&mut self, name: S) -> &mut Self {
        self.public_name = Some(name.into());
        self
    }

    /// Dump functions at the given address
    pub fn address(&mut self, addr: VAddr) -> &mut Self {
        self.addr = Some(addr);
        self
    }

    fn create_dot(&self, func: &Function) -> std::io::Result<()> {
        let mut stream = File::create(&self.filename)?;

        write!(stream, "digraph CFG {{")?;
        write!(stream, "graph [center=true];")?;
        write!(stream, "root [shape=point];")?;
        write!(stream, "root -> bb_{};", func.cfg().entry())?;

        for bb in func.cfg().iter_basic_blocks() {
            write!(stream, "bb_{0} [shape=\"rect\", label=\"[{0}] ", bb.id())?;

            if let Some(vaddr) = bb.vaddr() {
                write!(stream, "{:#x}:\\n", vaddr)?;
            } else {
                write!(stream, "artificial:\\n")?;
            }

            for op in bb.ops() {
                write!(stream, "{:?}\\n", op)?;
            }

            write!(stream, "\"];")?;

            for edge in bb.edges() {
                let color = match edge {
                    Edge::Next(_) => "red",
                    Edge::Jump(_) => "green",
                };
                write!(stream, "bb_{} -> bb_{} [color=\"{}\"];", bb.id(), edge.target(), color)?;
            }
        }

        writeln!(stream, "}}")?;
        stream.flush()
    }
}

impl Pass for FunctionDOTPass {
    type Error = std::io::Error;

    fn name(&self) -> String {
        "FunctionDOTPass".to_string()
    }

    fn run(&mut self, image: &mut ProcessImage, _event_pool: &mut EventPool, _logger: &Logger) -> Result<(), Self::Error> {
        for elf in image.iter_elfs() {
            for section in elf.iter_sections() {
                for symbol in section.iter_symbols() {
                    let mut found = false;

                    found |= if let Some(name) = &self.public_name { symbol.public_name(name).is_some() } else { false };

                    found |= if let Some(name) = &self.private_name { symbol.private_name(name).is_some() } else { false };

                    for chunk in symbol.iter_chunks() {
                        found |= if let Some(addr) = &self.addr { chunk.contains_address(*addr) } else { false };

                        if found {
                            if let ChunkContent::Code(func) = chunk.content() {
                                self.create_dot(func)?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
