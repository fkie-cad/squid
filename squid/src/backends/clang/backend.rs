use std::{
    collections::{
        BTreeMap,
        HashMap,
    },
    hash::{
        BuildHasher,
        Hash,
        Hasher,
    },
    path::PathBuf,
};

use ahash::RandomState;
use thiserror::Error;

use crate::{
    backends::{
        clang::{
            codegen::CLifterError,
            concretize,
            get_entrypoint_address,
            insert_entrypoint,
            insert_guard_pages,
            populate_stack,
            symbol::create_symbol_store,
            AddressLayouter,
            CLifter,
            ClangRuntime,
            EventChannel,
            Memory,
            Registers,
            VariableStorage,
        },
        Backend,
    },
    event::EventPool,
    frontend::ProcessImage,
    riscv::register::GpRegister,
    Logger,
};

/// The ClangBackendBuilder configures the [`ClangBackend`] with the values
/// that you provide.
/// Use the [`ClangBackend::builder`] method to create this builder.
pub struct ClangBackendBuilder {
    source_file: Option<PathBuf>,
    heap_size: usize,
    stack_size: Option<usize>,
    env: BTreeMap<String, String>,
    args: Vec<String>,
    build_symbol_table: bool,
    update_pc: bool,
    update_last_instr: bool,
    timeout: usize,
    count_instructions: bool,
    cflags: Vec<String>,
    cc: String,
    uninit_stack: bool,
    allow_div_by_zero: bool,
}

impl ClangBackendBuilder {
    /// Do not throw an error when dividing by zero and set the result to 0 instead (default: `false`)
    pub fn allow_div_by_zero(mut self, flag: bool) -> Self {
        self.allow_div_by_zero = flag;
        self
    }
    
    /// Whenever a stackframe is allocated or deallocated, mark its contents as uninitialized (default: `true`)
    pub fn enable_uninit_stack(mut self, flag: bool) -> Self {
        self.uninit_stack = flag;
        self
    }

    /// Set the compiler to use for compiling the AOT-code
    pub fn cc<S: Into<String>>(mut self, cc: S) -> Self {
        self.cc = cc.into();
        self
    }

    /// Pass this flag to the c compiler when AOT-compiling the code
    pub fn cflag<S: Into<String>>(mut self, arg: S) -> Self {
        self.cflags.push(arg.into());
        self
    }

    /// Store the AOT-code into this file
    pub fn source_file<P: Into<PathBuf>>(mut self, source_file: P) -> Self {
        self.source_file = Some(source_file.into());
        self
    }

    /// Generate a [`ClangRuntimeFault::Timeout`](crate::backends::clang::ClangRuntimeFault::Timeout) error after the given number of RISC-V instructions
    pub fn timeout(mut self, timeout: usize) -> Self {
        self.timeout = timeout;
        self
    }

    /// If this is set to true, the backend emits code that tracks how many RISC-V instructions were executed each run.
    /// The number of instructions can be access via [`ClangRuntime::get_executed_instructions`](crate::backends::clang::ClangRuntime::get_executed_instructions).
    pub fn count_instructions(mut self, flag: bool) -> Self {
        self.count_instructions = flag;
        self
    }

    /// If this is set to true, build a symbol table in the runtime with all the names from the process image
    pub fn build_symbol_table(mut self, flag: bool) -> Self {
        self.build_symbol_table = flag;
        self
    }

    /// If this is set to true, the backend emits code that updates the pc with the address of the basic block that has been executed last
    pub fn update_pc(mut self, flag: bool) -> Self {
        self.update_pc = flag;
        self
    }

    /// If this is set to true, the backend emits code that stores which RISC-V instruction was executed last. Note that this is the virtual address
    /// of the RISC-V instruction inside the ELF file and has nothing to do with the virtual address the ClangRuntime uses.
    /// You can access this value in the runtime via the [`ClangRuntime::get_last_instruction`](crate::backends::clang::ClangRuntime::get_last_instruction) method.
    pub fn update_last_instruction(mut self, flag: bool) -> Self {
        self.update_last_instr = flag;
        self
    }

    /// Set the size of the heap in bytes
    pub fn heap_size(mut self, heap_size: usize) -> Self {
        self.heap_size = heap_size;
        self
    }

    /// Set the size of the stack in bytes
    pub fn stack_size(mut self, stack_size: usize) -> Self {
        self.stack_size = Some(stack_size);
        self
    }

    /// Insert an environment variable into the environment of the guest
    pub fn env<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add the argument to the argv of the guest
    pub fn arg<S>(mut self, arg: S) -> Self
    where
        S: Into<String>,
    {
        self.args.push(arg.into());
        self
    }

    /// Add multiple args to the argv of the guest
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for arg in args {
            self.args.push(arg.into());
        }
        self
    }

    /// Set argv\[0\] of the guest to the given name
    pub fn progname<S>(mut self, progname: S) -> Self
    where
        S: Into<String>,
    {
        if let Some(arg) = self.args.get_mut(0) {
            *arg = progname.into();
        } else {
            self.args.push(progname.into());
        }
        self
    }

    /// Create the [`ClangBackend`]
    pub fn build(self) -> Result<ClangBackend, &'static str> {
        let source_file = self.source_file.ok_or("Source file was not set")?;
        let stack_size = self.stack_size.ok_or("Stack size was not set")?;

        Ok(ClangBackend {
            source_file,
            heap_size: self.heap_size,
            stack_size,
            env: self.env,
            args: self.args,
            symbol_store: self.build_symbol_table,
            update_pc: self.update_pc,
            update_last_instr: self.update_last_instr,
            timeout: self.timeout,
            count_instructions: self.count_instructions,
            cflags: self.cflags,
            cc: self.cc,
            uninit_stack: self.uninit_stack,
            allow_div_by_zero: self.allow_div_by_zero,
        })
    }
}

/// This error shows everything that can go wrong during the operations of the ClangBackend.
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ClangBackendError {
    #[error("Codegen failed: {0}")]
    CodegenError(#[from] CLifterError),

    #[error("Could not populate stack (not enough memory?)")]
    StackError,
}

/// The ClangBackend generates C code from the code in the process image and compiles that
/// with clang for optimal codegen. It constructs the [`ClangRuntime`].
pub struct ClangBackend {
    source_file: PathBuf,
    heap_size: usize,
    stack_size: usize,
    env: BTreeMap<String, String>,
    args: Vec<String>,
    symbol_store: bool,
    update_pc: bool,
    update_last_instr: bool,
    timeout: usize,
    count_instructions: bool,
    cflags: Vec<String>,
    cc: String,
    uninit_stack: bool,
    allow_div_by_zero: bool,
}

impl ClangBackend {
    /// Create a [`ClangBackendBuilder`] that can configure this backend.
    pub fn builder() -> ClangBackendBuilder {
        ClangBackendBuilder {
            source_file: None,
            heap_size: 0,
            stack_size: None,
            env: BTreeMap::new(),
            args: Vec::new(),
            build_symbol_table: true,
            update_pc: true,
            update_last_instr: true,
            timeout: 800_000_000 * 60,
            count_instructions: true,
            cflags: Vec::new(),
            cc: "clang".to_string(),
            uninit_stack: true,
            allow_div_by_zero: false,
        }
    }
}

impl ClangBackend {
    fn config_hash(&self, image: &ProcessImage) -> u64 {
        let mut hasher = RandomState::with_seeds(1, 1, 1, 1).build_hasher();
        hasher.write_usize(self.heap_size);
        hasher.write_usize(self.stack_size);
        hasher.write_u8(self.update_pc as u8);
        hasher.write_u8(self.update_last_instr as u8);
        hasher.write_usize(self.timeout);
        hasher.write_u8(self.count_instructions as u8);
        hasher.write_u8(self.uninit_stack as u8);
        hasher.write_u8(self.allow_div_by_zero as u8);
        for cflag in &self.cflags {
            hasher.write_usize(cflag.len());
            hasher.write(cflag.as_bytes());
        }
        hasher.write_usize(self.cc.len());
        hasher.write(self.cc.as_bytes());
        image.hash(&mut hasher);
        hasher.finish()
    }
}

impl Backend for ClangBackend {
    type Runtime = ClangRuntime;
    type Error = ClangBackendError;

    fn name(&self) -> String {
        "ClangBackend".to_string()
    }

    fn create_runtime(&mut self, mut image: ProcessImage, event_pool: EventPool, logger: &Logger) -> Result<Self::Runtime, Self::Error> {
        /* Add missing things to progam image */
        insert_entrypoint(&mut image, &event_pool);
        insert_guard_pages(&mut image);

        /* Assign new virtual addresses to the elements in the process image */
        let mut layouter = AddressLayouter::new();
        layouter.layout(&mut image);

        /* Concretize symbolic pointers */
        concretize(&mut image);

        /* Create the event channel */
        let event_channel = EventChannel::new(&image);

        /* Create the registers */
        let mut registers = Registers::new();

        /* Build memory for runtime */
        let mut memory = Memory::new(&image, layouter.globals_size(), self.heap_size, self.stack_size);

        /* Create variable storage */
        let varstore = VariableStorage::new(&image);

        /* Compile the code */
        let config_hash = self.config_hash(&image);
        let mut clifter = CLifter::new(
            self.source_file.clone(),
            self.update_pc,
            self.update_last_instr,
            self.timeout,
            self.count_instructions,
            config_hash,
            layouter.code_size(),
            self.uninit_stack,
            self.allow_div_by_zero,
        );
        let executor = clifter.lift(&image, &memory, &varstore, logger, &self.cflags, &self.cc)?;

        /* Print some stats */
        logger.info(format!("Size of memory: {} bytes", memory.size()));
        logger.info(format!("Size of static variable storage: {}", varstore.num_variables() * 8));
        logger.info(format!("Size of event channel: {}", event_channel.capacity()));

        /* Get entrypoint */
        let entrypoint = get_entrypoint_address(&image);
        registers.set_pc(entrypoint);

        /* Create stack */
        let sp = populate_stack(&mut memory, &self.args, &self.env).ok_or(ClangBackendError::StackError)?;
        registers.set_gp(GpRegister::sp as usize, sp);
        memory.clear_dirty_stack();

        /* Create the symbol store */
        let symbols = if self.symbol_store { create_symbol_store(&image) } else { HashMap::default() };

        Ok(ClangRuntime::new(memory, event_channel, registers, executor, entrypoint, symbols, vec![0; varstore.num_variables()]))
    }
}
