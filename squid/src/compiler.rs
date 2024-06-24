use std::{
    convert::AsRef,
    path::Path,
};

use thiserror::Error;

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
        VerifyerPassError,
    },
};

#[derive(Error, Debug)]
pub enum CompilationError<E: std::error::Error> {
    #[error("The backend had an error: {0}")]
    BackendError(E),

    #[error("Verification failed: {0}")]
    VerificationError(#[from] VerifyerPassError),
}

/// The Compiler is the center piece of `squid`. It loads ELF files, runs passes and launches a backend
/// to obtain a [Runtime](crate::runtime::Runtime).
/// 
/// To obtain a `Compiler` instance, call [`Compiler::load_elf`]. Then you can run one or more passes
/// with [`Compiler::run_pass`] before compiling the process image with [`Compiler::compile`].
#[derive(Debug)]
pub struct Compiler {
    pub(crate) image: ProcessImage,
    pub(crate) event_pool: EventPool,
    modified: bool,
}

impl Compiler {
    /// Symbolically load an ELF file and create a process image.
    /// 
    /// # Arguments
    /// 1. `binary`: Path to the ELF binary that is being run by `squid`
    /// 2. `search_paths`: Similar to LD_LIBRARY_PATH, a list of directory names where the binaries dependencies
    ///    are searched
    /// 3. `preloads`: Similar to LD_PRELOAD, a list of shared objects that are to be preloaded into the process image
    ///     before all other dependencies
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

        compiler.verify()?;
        Ok(compiler)
    }

    /// Run a pass to inspect or modify the process image.
    /// 
    /// # Arguments
    /// 1. `pass`: Anything that implements the [`Pass`] trait
    pub fn run_pass<P>(&mut self, pass: &mut P) -> Result<(), P::Error>
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

    fn verify(&mut self) -> Result<(), VerifyerPassError> {
        let mut verifyer = VerifyerPass::new(false);
        self.run_pass(&mut verifyer)?;
        self.modified = false;
        Ok(())
    }

    /// Compile the process image and create a [Runtime](crate::runtime::Runtime).
    /// The type of the runtime is determined by the backend. Each backend can have its own runtime.
    /// 
    /// # Arguments
    /// 1. `backend`: Anything that implements the [`Backend`] trait
    pub fn compile<B: Backend>(mut self, mut backend: B) -> Result<B::Runtime, CompilationError<B::Error>> {
        if self.modified {
            self.verify()?;
        }

        let mut logger = Logger::spinner();
        logger.set_title(format!("Compiling with backend: {}", backend.name()));
        logger.set_prefix(backend.name());

        let ret = match backend.create_runtime(self.image, self.event_pool, &logger) {
            Ok(runtime) => runtime,
            Err(err) => return Err(CompilationError::BackendError(err)),
        };

        logger.clear_prefix();
        logger.info("Compilation successful");
        Ok(ret)
    }

    /// Access the process image, which is the result of symbolically loading a binary
    pub fn process_image(&self) -> &ProcessImage {
        &self.image
    }

    /// Access the event pool
    pub fn event_pool(&self) -> &EventPool {
        &self.event_pool
    }
}
