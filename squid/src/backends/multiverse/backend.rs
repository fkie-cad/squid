use std::{
    collections::{
        BTreeMap,
        HashMap,
    },
    hash::{
        BuildHasher,
        Hasher,
    },
    path::PathBuf,
};

use ahash::RandomState;
use thiserror::Error;

use crate::{
    backends::{
        multiverse::{
            codegen::CLifterError,
            concretize,
            get_entrypoint_address,
            insert_entrypoint,
            insert_null_page,
            perms,
            populate_stack,
            symbol::create_symbol_store,
            AddressLayouter,
            CLifter,
            EventChannel,
            Memory,
            MultiverseRuntime,
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

pub struct MultiverseBackendBuilder {
    source_file: Option<PathBuf>,
    heap_size: Option<usize>,
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
}

impl MultiverseBackendBuilder {
    pub fn cc<S: Into<String>>(mut self, cc: S) -> Self {
        self.cc = cc.into();
        self
    }

    pub fn cflag<S: Into<String>>(mut self, arg: S) -> Self {
        self.cflags.push(arg.into());
        self
    }

    pub fn source_file<P: Into<PathBuf>>(mut self, source_file: P) -> Self {
        self.source_file = Some(source_file.into());
        self
    }

    pub fn timeout(mut self, timeout: usize) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn count_instructions(mut self, flag: bool) -> Self {
        self.count_instructions = flag;
        self
    }

    pub fn build_symbol_table(mut self, flag: bool) -> Self {
        self.build_symbol_table = flag;
        self
    }

    pub fn update_pc(mut self, flag: bool) -> Self {
        self.update_pc = flag;
        self
    }

    pub fn update_last_instruction(mut self, flag: bool) -> Self {
        self.update_last_instr = flag;
        self
    }

    pub fn heap_size(mut self, heap_size: usize) -> Self {
        self.heap_size = Some(heap_size);
        self
    }

    pub fn stack_size(mut self, stack_size: usize) -> Self {
        self.stack_size = Some(stack_size);
        self
    }

    pub fn env<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn arg<S>(mut self, arg: S) -> Self
    where
        S: Into<String>,
    {
        self.args.push(arg.into());
        self
    }

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

    pub fn build(self) -> Result<MultiverseBackend, &'static str> {
        let source_file = self.source_file.ok_or("Source file was not set")?;
        let heap_size = self.heap_size.ok_or("Heap size was not set")?;
        let stack_size = self.stack_size.ok_or("Stack size was not set")?;

        Ok(MultiverseBackend {
            source_file,
            heap_size,
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
        })
    }
}

#[derive(Error, Debug)]
pub enum MultiverseBackendError {
    #[error("One of the ELF files makes use of thread local storage, which is not supported by this backend")]
    HasTls,

    #[error("Codegen failed: {0}")]
    CodegenError(#[from] CLifterError),

    #[error("Could not populate stack (not enough memory?)")]
    StackError,
}

pub struct MultiverseBackend {
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
}

impl MultiverseBackend {
    pub fn builder() -> MultiverseBackendBuilder {
        MultiverseBackendBuilder {
            source_file: None,
            heap_size: None,
            stack_size: None,
            env: BTreeMap::new(),
            args: Vec::new(),
            build_symbol_table: true,
            update_pc: true,
            update_last_instr: true,
            timeout: 400_000_000 * 180,
            count_instructions: true,
            cflags: Vec::new(),
            cc: "clang".to_string(),
        }
    }
}

impl MultiverseBackend {
    fn config_hash(&self) -> u64 {
        let mut hasher = RandomState::with_seeds(1, 1, 1, 1).build_hasher();
        hasher.write_usize(self.heap_size);
        hasher.write_usize(self.stack_size);
        hasher.write_u8(self.update_pc as u8);
        hasher.write_u8(self.update_last_instr as u8);
        hasher.write_usize(self.timeout);
        hasher.write_u8(self.count_instructions as u8);
        for cflag in &self.cflags {
            hasher.write_usize(cflag.len());
            hasher.write(cflag.as_bytes());
        }
        hasher.write_usize(self.cc.len());
        hasher.write(self.cc.as_bytes());
        hasher.finish()
    }
}

impl Backend for MultiverseBackend {
    type Runtime = MultiverseRuntime;
    type Error = MultiverseBackendError;

    fn name(&self) -> String {
        "MultiverseBackend".to_string()
    }

    fn create_runtime(&mut self, mut image: ProcessImage, event_pool: EventPool, logger: &Logger) -> Result<Self::Runtime, Self::Error> {
        /* Check if there is TLS anywhere */
        for elf in image.iter_elfs() {
            if elf.tls().num_thread_locals() > 0 {
                return Err(MultiverseBackendError::HasTls);
            }
        }

        /* Add missing things to progam image */
        insert_entrypoint(&mut image, &event_pool);
        insert_null_page(&mut image);

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
        let globals = Memory::new_globals(&image, layouter.globals_size());
        let heap = Memory::new_uninit(self.heap_size, perms::PERM_NONE);
        let mut stack = Memory::new_uninit(self.stack_size, perms::PERM_NONE);

        /* Create variable storage */
        let varstore = VariableStorage::new(&image);

        /* Compile the code */
        let config_hash = self.config_hash();
        let mut clifter = CLifter::new(self.source_file.clone(), self.update_pc, self.update_last_instr, self.timeout, self.count_instructions, config_hash, layouter.code_size());
        let executor = clifter.lift(&image, &globals, &heap, &stack, &varstore, logger, &self.cflags, &self.cc)?;

        /* Print some stats */
        logger.info(format!("Size of global variables: {} bytes", globals.size()));
        logger.info(format!("Size of heap: {} bytes", heap.size()));
        logger.info(format!("Size of stack: {} bytes", stack.size()));
        logger.info(format!("Size of static variable storage: {}", varstore.num_variables() * 8));
        logger.info(format!("Size of event channel: {}", event_channel.capacity()));

        /* Get entrypoint */
        let entrypoint = get_entrypoint_address(&image);
        registers.set_pc(entrypoint);

        /* Create stack */
        let sp = populate_stack(&mut stack, &self.args, &self.env).ok_or(MultiverseBackendError::StackError)?;
        registers.set_gp(GpRegister::sp as usize, sp);
        stack.clear_dirty_stack();

        /* Create the symbol store */
        let symbols = if self.symbol_store { create_symbol_store(&image) } else { HashMap::default() };

        Ok(MultiverseRuntime::new(globals, heap, stack, event_channel, registers, executor, entrypoint, symbols, vec![0; varstore.num_variables()]))
    }
}
