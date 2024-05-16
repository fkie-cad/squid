use std::collections::HashSet;
use thiserror::Error;
use crate::{
    event::EventPool,
    frontend::{
        ao::{
            events::EVENT_BREAKPOINT,
            BasicBlock,
            Edge,
            Function,
        },
        ChunkContent,
        ProcessImage,
        VAddr,
    },
    logger::Logger,
    passes::Pass,
};

#[derive(Error, Debug)]
#[error("BreakpointPassError")]
pub struct BreakpointPassError;

pub struct BreakpointPass {
    private_names: HashSet<String>,
    public_names: HashSet<String>,
    addrs: HashSet<VAddr>,
    all: bool,
}

impl BreakpointPass {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            private_names: HashSet::new(),
            public_names: HashSet::new(),
            addrs: HashSet::new(),
            all: false,
        }
    }

    pub fn all(&mut self) -> &mut Self {
        self.all = true;
        self
    }

    pub fn private_name<S: Into<String>>(&mut self, name: S) -> &mut Self {
        self.private_names.insert(name.into());
        self
    }

    pub fn public_name<S: Into<String>>(&mut self, name: S) -> &mut Self {
        self.public_names.insert(name.into());
        self
    }

    pub fn address(&mut self, addr: VAddr) -> &mut Self {
        self.addrs.insert(addr);
        self
    }

    fn instrument(&self, func: &mut Function, event_pool: &EventPool) {
        let breakpoint = event_pool.get_event(EVENT_BREAKPOINT).unwrap();

        let mut bb = BasicBlock::new();
        bb.fire_event(breakpoint);

        let entry = func.cfg().entry();
        bb.add_edge(Edge::Next(entry));

        let id = func.cfg_mut().add_basic_block(bb);
        func.cfg_mut().set_entry(id);

        assert_ne!(entry, id);
    }
}

impl Pass for BreakpointPass {
    type Error = BreakpointPassError;

    fn name(&self) -> String {
        "BreakpointPass".to_string()
    }

    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), Self::Error> {
        let mut count = 0;

        for elf in image.iter_elfs_mut() {
            for section in elf.iter_sections_mut() {
                for symbol in section.iter_symbols_mut() {
                    let mut found = self.all;

                    /* Check if it matches a public name */
                    if !found {
                        for name in &self.public_names {
                            if symbol.public_name(name).is_some() {
                                found = true;
                                break;
                            }
                        }
                    }

                    /* Check if it matches a private name */
                    if !found {
                        for name in &self.private_names {
                            if symbol.private_name(name).is_some() {
                                found = true;
                                break;
                            }
                        }
                    }

                    for chunk in symbol.iter_chunks_mut() {
                        /* Check if the address matches */
                        if !found {
                            found |= self.addrs.contains(&chunk.vaddr());
                        }

                        if found {
                            if let ChunkContent::Code(func) = chunk.content_mut() {
                                self.instrument(func, event_pool);
                                count += 1;
                            }
                        }
                    }
                }
            }
        }

        logger.info(format!("Set {} breakpoints", count));

        Ok(())
    }
}
