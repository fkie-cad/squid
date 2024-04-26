use std::{
    convert::AsRef,
    path::Path,
};

use crate::{
    backends::Backend,
    event::EventPool,
    frontend::{
        ao::events::{
            EVENT_BREAKPOINT,
            EVENT_SYSCALL,
        },
        LoaderError,
        ProcessImage,
        ProcessImageBuilder,
    },
    logger::Logger,
    passes::{
        Pass,
        VerifyerPass,
    },
};

#[derive(Debug)]
pub struct Compiler {
    pub(crate) image: ProcessImage,
    pub(crate) event_pool: EventPool,
    modified: bool,
}

impl Compiler {
    pub fn load_elf<S>(binary: S, search_paths: &[S], preloads: &[S]) -> Result<Self, LoaderError>
    where
        S: AsRef<Path>,
    {
        let mut logger = Logger::spinner();
        logger.set_title("Building process image");

        let mut event_pool = EventPool::new();
        event_pool.add_event(EVENT_SYSCALL);
        event_pool.add_event(EVENT_BREAKPOINT);

        let image = ProcessImageBuilder::build(binary, search_paths, preloads, &mut event_pool, &logger)?;
        let mut compiler = Self {
            image,
            event_pool,
            modified: false,
        };

        drop(logger);

        if let Err(msg) = compiler.verify() {
            return Err(LoaderError::InvalidProcessImage(msg));
        }

        Ok(compiler)
    }

    pub fn run_pass<P>(&mut self, pass: &mut P) -> Result<(), String>
    where
        P: Pass,
    {
        self.modified = true;

        let mut logger = Logger::spinner();
        logger.set_title(format!("Running Pass: {}", pass.name()));
        logger.set_prefix(pass.name());

        let ret = pass.run(&mut self.image, &mut self.event_pool, &logger);

        logger.clear_prefix();
        ret
    }

    fn verify(&mut self) -> Result<(), String> {
        let mut verifyer = VerifyerPass::new(false);
        self.run_pass(&mut verifyer)?;
        self.modified = false;
        Ok(())
    }

    pub fn compile<B: Backend>(mut self, mut backend: B) -> Result<B::Runtime, String> {
        if self.modified {
            self.verify()?;
        }

        let mut logger = Logger::spinner();
        logger.set_title(format!("Compiling with backend: {}", backend.name()));
        logger.set_prefix(backend.name());

        let ret = backend.create_runtime(self.image, self.event_pool, &logger)?;

        logger.clear_prefix();
        logger.info("Compilation successful");
        Ok(ret)
    }

    pub fn process_image(&self) -> &ProcessImage {
        &self.image
    }

    pub fn event_pool(&self) -> &EventPool {
        &self.event_pool
    }
}
