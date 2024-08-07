use std::path::PathBuf;

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
pub enum CompilerError<'a> {
    #[error("Loader has not been configured correctly: {0}")]
    LoaderOptionNotSet(&'static str),
    
    #[error("The frontend had an error: {0}")]
    LoaderError(#[from] LoaderError),
    
    #[error("The backend had an error: {0}")]
    BackendError(Box<dyn std::error::Error + 'a>),

    #[error("Verification failed: {0}")]
    VerificationError(#[from] VerifyerPassError),
}

/// The `Loader` is a helper struct that creates a [`Compiler`] by
/// - Loading an ELF file
/// - collecting its shared dependencies
/// - lifting all RISC-V code into an IR
/// - making code and data available in a [`ProcessImage`]
pub struct Loader {
    binary: Option<PathBuf>,
    library_paths: Vec<PathBuf>,
    preloads: Vec<PathBuf>,
    ignore_missing_deps: bool,
}

impl Loader {
    pub(crate) fn new() -> Self {
        Self {
            binary: None,
            library_paths: Vec::new(),
            preloads: Vec::new(),
            ignore_missing_deps: false,
        }
    }
    
    /// Set the target binary that is going to be emulated
    pub fn binary<P: Into<PathBuf>>(mut self, binary: P) -> Self {
        self.binary = Some(binary.into());
        self
    }
    
    /// Add the given directory to the search paths of the ELF loader. 
    /// The shared dependencies of the binary will be searched here (similar to LD_LIBRARY_PATH).
    /// You can specify this option multiple times.
    pub fn search_path<P: Into<PathBuf>>(mut self, search_path: P) -> Self {
        self.library_paths.push(search_path.into());
        self
    }
    
    /// Add multiple directories to the search paths of the ELF loader.
    /// Does the same as [`Loader::search_path`].
    pub fn search_paths<I, P>(mut self, search_paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for search_path in search_paths {
            self.library_paths.push(search_path.into());
        }
        self
    }
    
    /// Preload this library (similar to LD_PRELOAD).
    /// You can specify this option multiple times.
    pub fn preload<P: Into<PathBuf>>(mut self, library: P) -> Self {
        self.preloads.push(library.into());
        self
    }
    
    /// Preload multiple libraries.
    /// Does the same as [`Loader::preload`].
    pub fn preloads<I, P>(mut self, preloads: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        for preload in preloads {
            self.preloads.push(preload.into());
        }
        self
    }
    
    /// If `flag` is set to `true`, the ELF loader will not throw an error when it cannot
    /// find a dependency in the provided search paths.
    pub fn ignore_missing_dependencies(mut self, flag: bool) -> Self {
        self.ignore_missing_deps = flag;
        self
    }
    
    /// Create a [`Compiler`] by loading the target binary
    pub fn load(self) -> Result<Compiler, CompilerError<'static>> {
        let binary = self.binary.ok_or(CompilerError::LoaderOptionNotSet("binary has not been set"))?;
        
        let mut logger = Logger::spinner();
        logger.set_title("Building process image");

        let mut event_pool = EventPool::new();
        event_pool.add_event(EVENT_SYSCALL);
        event_pool.add_event(EVENT_BREAKPOINT);

        let image = ProcessImageBuilder::build(binary, &self.library_paths, &self.preloads, self.ignore_missing_deps, &mut event_pool, &logger)?;
        let mut compiler = Compiler {
            image,
            event_pool,
            modified: false,
        };
        drop(logger);

        compiler.verify()?;
        Ok(compiler)
    }
}

/// The Compiler is the center piece of `squid`. It loads ELF files, runs passes and launches a backend
/// to obtain a [Runtime](crate::runtime::Runtime).
///
/// To obtain a `Compiler` instance, call [`Compiler::loader`]. Then you can run one or more passes
/// with [`Compiler::run_pass`] before compiling the process image with [`Compiler::compile`].
#[derive(Debug)]
pub struct Compiler {
    pub(crate) image: ProcessImage,
    pub(crate) event_pool: EventPool,
    modified: bool,
}

impl Compiler {
    /// Create a new `Compiler` by symbolically loading an ELF file and creating a process image.
    /// See the [`Loader`] for details about how the ELF-loader can be configured.
    pub fn loader() -> Loader {
        Loader::new()
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
    pub fn compile<'a, B: Backend>(mut self, mut backend: B) -> Result<B::Runtime, CompilerError<'a>>
    where
        <B as Backend>::Error: 'a,
    {
        if self.modified {
            self.verify()?;
        }

        let mut logger = Logger::spinner();
        logger.set_title(format!("Compiling with backend: {}", backend.name()));
        logger.set_prefix(backend.name());

        let ret = match backend.create_runtime(self.image, self.event_pool, &logger) {
            Ok(runtime) => runtime,
            Err(err) => return Err(CompilerError::BackendError(Box::new(err))),
        };

        logger.clear_prefix();
        logger.info("Compilation successful");
        Ok(ret)
    }

    /// Access the process image, which is the result of symbolically loading a binary
    pub fn process_image(&self) -> &ProcessImage {
        &self.image
    }

    /// Access the event pool, which manages all events that can be thrown at runtime
    pub fn event_pool(&self) -> &EventPool {
        &self.event_pool
    }
}
