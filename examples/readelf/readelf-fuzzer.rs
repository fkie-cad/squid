use std::{
    borrow::Cow,
    ffi::OsStr,
    marker::PhantomData,
    path::PathBuf,
};

use clap::Parser;
use libafl::prelude::{
    feedback_or,
    havoc_mutations,
    powersched::PowerSchedule,
    AggregatorOps,
    BytesInput,
    CachedOnDiskCorpus,
    CalibrationStage,
    CanTrack,
    CrashFeedback,
    Event,
    EventConfig,
    EventFirer,
    Executor,
    ExitKind,
    Feedback,
    ForkserverExecutor,
    Fuzzer,
    HasExecutions,
    HasMutatorBytes,
    HasObservers,
    HitcountsMapObserver,
    InMemoryCorpus,
    IndexesLenTimeMinimizerScheduler,
    Input,
    Launcher,
    LlmpRestartingEventManager,
    MaxMapFeedback,
    MultiMonitor,
    NopMonitor,
    Observer,
    ObserversTuple,
    OnDiskCorpus,
    OnDiskJSONMonitor,
    SimpleEventManager,
    State,
    StdFuzzer,
    StdMOptMutator,
    StdMapObserver,
    StdPowerMutationalStage,
    StdScheduler,
    StdState,
    StdWeightedScheduler,
    Testcase,
    TimeFeedback,
    TimeObserver,
    TimeoutFeedback,
    UserStats,
    UserStatsValue,
    UsesInput,
    UsesObservers,
    UsesState,
};
use libafl_bolts::prelude::{
    current_nanos,
    current_time,
    tuple_list,
    AsSliceMut,
    CoreId,
    Cores,
    Error,
    Handle,
    Handled,
    MatchNameRef,
    Named,
    OwnedMutSlice,
    RefIndexable,
    ShMem,
    ShMemProvider,
    StdRand,
    StdShMemProvider,
    UnixShMemProvider,
};
use mimalloc::MiMalloc;
use squid::{
    backends::clang::{
        perms::*,
        ClangBackend,
        ClangRuntime,
        ClangRuntimeFault,
        HeapError,
    },
    event::EventPool,
    frontend::{
        ao::{
            events::*,
            ArithmeticBehavior,
            BasicBlock,
            Edge,
            Op,
        },
        Chunk,
        ChunkContent,
        Elf,
        GlobalPointer,
        HasId,
        Perms,
        Pointer,
        ProcessImage,
        Section,
        Symbol,
        VAddr,
    },
    kernel::{
        fs,
        linux::{
            Linux,
            LinuxError,
        },
        structs::Stat,
    },
    passes::{
        AsanPass,
        BreakpointPass,
        NoPassError,
        Pass,
    },
    riscv::{
        register::GpRegister,
        syscalls,
    },
    runtime::Runtime,
    Compiler,
    Logger,
};
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

struct CoveragePass {}

impl CoveragePass {
    fn new() -> Self {
        Self {}
    }
}

impl Pass for CoveragePass {
    type Error = NoPassError;

    fn name(&self) -> String {
        "CoveragePass".to_string()
    }

    fn run(
        &mut self,
        image: &mut ProcessImage,
        _event_pool: &mut EventPool,
        logger: &Logger,
    ) -> Result<(), Self::Error> {
        /* Find id of binary */
        let mut target_id = None;

        for elf in image.iter_elfs() {
            if elf.path().file_name() == Some(OsStr::new("readelf")) {
                target_id = Some(elf.id());
                break;
            }
        }

        let target_id = target_id.unwrap();

        /* Find out the size of the coverage map */
        let mut coverage_map_size = 0;

        let elf = image.elf(target_id).unwrap();
        for section in elf.iter_sections() {
            for symbol in section.iter_symbols() {
                for chunk in symbol.iter_chunks() {
                    if let ChunkContent::Code(func) = chunk.content() {
                        for _ in func.cfg().iter_basic_blocks() {
                            coverage_map_size += 1;
                        }
                    }
                }
            }
        }

        /* Construct the coverage map */
        let mut perms = Perms::default();
        perms.make_readable();
        perms.make_writable();

        let chunk = Chunk::builder().uninitialized_data(coverage_map_size, perms).vaddr(0).build().unwrap();

        let mut symbol =
            Symbol::builder().private_name("(coverage map)").vaddr(0).size(coverage_map_size).build().unwrap();

        let mut section = Section::builder().perms(perms).vaddr(0).size(coverage_map_size).build().unwrap();

        let mut elf = Elf::builder().path("<coverage map>").build().unwrap();

        let chunk_id = symbol.insert_chunk(chunk);
        let symbol_id = section.insert_symbol(symbol);
        let section_id = elf.insert_section(section);
        let elf_id = image.insert_elf(elf);

        /* Instrument the code */
        let mut cursor = 0;

        let elf = image.elf_mut(target_id).unwrap();
        for section in elf.iter_sections_mut() {
            for symbol in section.iter_symbols_mut() {
                for chunk in symbol.iter_chunks_mut() {
                    if let ChunkContent::Code(func) = chunk.content_mut() {
                        for bb in func.cfg_mut().iter_basic_blocks_mut() {
                            bb.set_cursor(0);
                            let ptr = bb.load_pointer(Pointer::Global(GlobalPointer {
                                elf: elf_id,
                                section: section_id,
                                symbol: symbol_id,
                                chunk: chunk_id,
                                offset: cursor,
                            }));
                            let old_value = bb.load_byte(ptr).unwrap();
                            let imm = bb.load_immediate(1);
                            let new_value = bb.add(old_value, imm, ArithmeticBehavior::Wrapping).unwrap();
                            bb.store_byte(ptr, new_value).unwrap();

                            cursor += 1;
                        }
                    }
                }
            }
        }

        assert_eq!(cursor, coverage_map_size);

        logger.info(format!("Instrumented {} locations", coverage_map_size));

        Ok(())
    }
}

struct SnapshotPass {}

impl SnapshotPass {
    const EVENT_NAME_TAKE_SNAPSHOT: &'static str = "snapshot::take_snapshot";
    const EVENT_NAME_RESTORE_SNAPSHOT: &'static str = "snapshot::restore_snapshot";

    fn new() -> Self {
        Self {}
    }
}

impl Pass for SnapshotPass {
    type Error = NoPassError;

    fn name(&self) -> String {
        "SnapshotPass".to_string()
    }

    fn run(
        &mut self,
        image: &mut ProcessImage,
        event_pool: &mut EventPool,
        _logger: &Logger,
    ) -> Result<(), Self::Error> {
        let event_take_snapshot = event_pool.add_event(Self::EVENT_NAME_TAKE_SNAPSHOT);
        let event_restore_snapshot = event_pool.add_event(Self::EVENT_NAME_RESTORE_SNAPSHOT);

        'image_loop: for elf in image.iter_elfs_mut() {
            if elf.path().ends_with("readelf") {
                for section in elf.iter_sections_mut() {
                    if !section.perms().is_executable() {
                        continue;
                    }

                    for symbol in section.iter_symbols_mut() {
                        if symbol.private_name("main").is_some() {
                            let chunk = symbol.iter_chunks_mut().next().unwrap();
                            let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };

                            /* Take snapshot at beginning of main() */
                            let entry = func.cfg().entry();

                            let mut new_bb = BasicBlock::new();
                            new_bb.fire_event(event_take_snapshot);
                            new_bb.add_edge(Edge::Next(entry));

                            let new_id = func.cfg_mut().add_basic_block(new_bb);

                            func.cfg_mut().set_entry(new_id);

                            /* Restore snapshot at the end of main() */
                            let mut addr = 0;
                            let mut last_id = None;

                            for bb in func.cfg().iter_basic_blocks() {
                                if let Some(bb_addr) = bb.vaddr() {
                                    if bb_addr > addr {
                                        addr = bb_addr;
                                        last_id = Some(bb.id());
                                    }
                                }
                            }

                            let last_id = last_id.unwrap();

                            let bb = func.cfg_mut().basic_block_mut(last_id).unwrap();
                            bb.move_cursor_beyond_end();
                            bb.move_cursor_backwards();

                            assert!(matches!(bb.cursor_op(), Some(Op::Jump { .. })));

                            bb.delete_op();
                            bb.fire_event(event_restore_snapshot);

                            break 'image_loop;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

const EVENT_ID_SYSCALL: usize = 0;
const EVENT_ID_BREAKPOINT: usize = 1;
const EVENT_ID_CALLOC: usize = 2;
const EVENT_ID_FREE: usize = 4;
const EVENT_ID_MALLOC: usize = 3;
const EVENT_ID_REALLOC: usize = 5;
const EVENT_ID_TAKE_SNAPSHOT: usize = 6;
const EVENT_ID_RESTORE_SNAPSHOT: usize = 7;

fn create_runtime(binaries: &str, output: &str, debug_build: bool) -> ClangRuntime {
    let mut compiler = Compiler::loader()
        .binary(format!("{}/readelf", binaries))
        .search_path(binaries)
        .load()
        .unwrap();

    compiler.run_pass(&mut AsanPass::new()).unwrap();
    compiler.run_pass(&mut CoveragePass::new()).unwrap();
    compiler.run_pass(&mut SnapshotPass::new()).unwrap();

    if debug_build {
        compiler.run_pass(BreakpointPass::new().all()).unwrap();
    }

    assert_eq!(compiler.event_pool().get_event(EVENT_SYSCALL).map(|x| x.id()), Some(EVENT_ID_SYSCALL));
    assert_eq!(compiler.event_pool().get_event(EVENT_BREAKPOINT).map(|x| x.id()), Some(EVENT_ID_BREAKPOINT));
    assert_eq!(compiler.event_pool().get_event(AsanPass::EVENT_NAME_MALLOC).map(|x| x.id()), Some(EVENT_ID_MALLOC));
    assert_eq!(compiler.event_pool().get_event(AsanPass::EVENT_NAME_FREE).map(|x| x.id()), Some(EVENT_ID_FREE));
    assert_eq!(compiler.event_pool().get_event(AsanPass::EVENT_NAME_REALLOC).map(|x| x.id()), Some(EVENT_ID_REALLOC));
    assert_eq!(compiler.event_pool().get_event(AsanPass::EVENT_NAME_CALLOC).map(|x| x.id()), Some(EVENT_ID_CALLOC));
    assert_eq!(
        compiler.event_pool().get_event(SnapshotPass::EVENT_NAME_TAKE_SNAPSHOT).map(|x| x.id()),
        Some(EVENT_ID_TAKE_SNAPSHOT)
    );
    assert_eq!(
        compiler.event_pool().get_event(SnapshotPass::EVENT_NAME_RESTORE_SNAPSHOT).map(|x| x.id()),
        Some(EVENT_ID_RESTORE_SNAPSHOT)
    );
    assert_eq!(compiler.event_pool().len(), 8);

    let source_file = if debug_build { format!("{}/jit_debug.c", output) } else { format!("{}/jit.c", output) };

    let mut builder = ClangBackend::builder()
        .heap_size(8 * 1024 * 1024)
        .stack_size(2 * 1024 * 1024)
        .progname("readelf")
        .arg("-W")
        .arg("-a")
        .arg("file")
        .build_symbol_table(true)
        .update_pc(cfg!(debug_assertions))
        .update_last_instruction(cfg!(debug_assertions))
        .count_instructions(true)
        .source_file(source_file);

    if debug_build {
        builder = builder.cflag("-O0").cflag("-g").cflag("-fno-omit-frame-pointer");
    } else {
        builder = builder
            .cflag("-Ofast")
            .cflag("-ffast-math")
            .cflag("-flto")
            .cflag("-s")
            .cflag("-fno-stack-protector")
            .cflag("-march=native")
            .cflag("-fomit-frame-pointer");
    }

    let backend = builder.build().unwrap();
    compiler.compile(backend).unwrap()
}

fn get_coverage_map(runtime: &mut ClangRuntime) -> OwnedMutSlice<'static, u8> {
    let symbols = runtime.lookup_symbol_from_private_name("(coverage map)");
    assert_eq!(symbols.len(), 1);
    let cov_map = symbols[0].1;
    let len = cov_map.size();
    let ptr = unsafe { runtime.raw_pointer_mut(cov_map.address()) }.unwrap();
    unsafe { OwnedMutSlice::from_raw_parts_mut(ptr, len) }
}

struct SquidExecutor<'a, S, OT>
where
    S: State,
    OT: ObserversTuple<S>,
{
    kernel: Linux<8>,
    observers: OT,
    handle: Handle<SquidObserver>,
    runtime: &'a mut ClangRuntime,
    phantom: PhantomData<S>,
}

impl<'a, S, OT> SquidExecutor<'a, S, OT>
where
    S: State,
    OT: ObserversTuple<S>,
{
    fn new(handle: Handle<SquidObserver>, observers: OT, runtime: &'a mut ClangRuntime) -> Self {
        let disk = fs::Fs::new();
        let mut kernel = Linux::new(disk, 0);

        kernel.take_snapshot(0);
        //runtime.take_snapshot(0);

        Self {
            kernel,
            observers,
            handle,
            runtime,
            phantom: PhantomData,
        }
    }

    #[inline]
    fn run(&mut self, fuzz_input: &[u8]) -> Result<usize, ClangRuntimeFault> {
        let mut num_instrs = 0;
        let runtime = &mut self.runtime;

        loop {
            match runtime.run()? {
                EVENT_ID_BREAKPOINT => {
                    #[cfg(debug_assertions)]
                    {
                        let pc = runtime.get_pc();
                        let symbols = runtime.lookup_symbol_from_address(pc);
                        println!("Breakpoint at pc={:#x} {:?}", pc, symbols);
                    }

                    #[cfg(not(debug_assertions))]
                    {
                        return Err(ClangRuntimeFault::InternalError("Breakpoint".to_string()));
                    }
                },
                EVENT_ID_SYSCALL => {
                    let a7 = runtime.get_gp_register(GpRegister::a7);

                    match a7 {
                        syscalls::set_tid_address => {
                            runtime.set_gp_register(GpRegister::a0, 1);
                        },
                        syscalls::exit | syscalls::exit_group => {
                            break;
                        },
                        syscalls::ioctl => {
                            let cmd = runtime.get_gp_register(GpRegister::a1);

                            match cmd {
                                libc::TIOCGWINSZ => {
                                    runtime.set_gp_register(GpRegister::a0, 0);
                                },
                                _ => {
                                    return Err(ClangRuntimeFault::InternalError(format!("ioctl: {}", cmd)));
                                },
                            }
                        },
                        syscalls::writev => {
                            #[cfg(debug_assertions)]
                            let fd = runtime.get_gp_register(GpRegister::a0);

                            let iov = runtime.get_gp_register(GpRegister::a1);
                            let iovcnt = runtime.get_gp_register(GpRegister::a2);

                            let mut ret = 0;

                            for i in 0..iovcnt {
                                let iov = iov + i * 16;
                                let iov_base = runtime.load_dword(iov)? as VAddr;
                                let iov_len = runtime.load_dword(iov + 8)? as usize;
                                let data = runtime.load_slice(iov_base, iov_len)?;

                                #[cfg(debug_assertions)]
                                {
                                    ret += self.kernel.write(fd as i32, data)?;
                                }

                                #[cfg(not(debug_assertions))]
                                {
                                    ret += data.len();
                                }
                            }

                            runtime.set_gp_register(GpRegister::a0, ret as u64);
                        },
                        syscalls::newfstatat => {
                            let a0 = runtime.get_gp_register(GpRegister::a0);
                            let a1 = runtime.get_gp_register(GpRegister::a1);
                            let a2 = runtime.get_gp_register(GpRegister::a2);
                            let a3 = runtime.get_gp_register(GpRegister::a3);

                            let filename = runtime.load_string(a1)?;

                            match filename {
                                b"file" => {
                                    let stat = self.kernel.fstatat_fuzz_input(fuzz_input.len());
                                    let charp = unsafe { std::mem::transmute::<*const Stat, *const u8>(&stat) };
                                    let contents =
                                        unsafe { std::slice::from_raw_parts(charp, std::mem::size_of::<Stat>()) };
                                    runtime.store_slice(a2, contents)?;
                                    runtime.set_gp_register(GpRegister::a0, 0);
                                },
                                _ => {
                                    if let Ok(filename) = std::str::from_utf8(filename) {
                                        match self.kernel.fstatat(a0 as i32, filename, a3 as i32) {
                                            Ok(stat) => {
                                                let charp =
                                                    unsafe { std::mem::transmute::<*const Stat, *const u8>(&stat) };
                                                let contents = unsafe {
                                                    std::slice::from_raw_parts(charp, std::mem::size_of::<Stat>())
                                                };
                                                runtime.store_slice(a2, contents)?;
                                                runtime.set_gp_register(GpRegister::a0, 0);
                                            },
                                            Err(err) => match err {
                                                LinuxError::FsError(_) => {
                                                    runtime
                                                        .set_gp_register(GpRegister::a0, -libc::ENOENT as i64 as u64);
                                                },
                                                _ => {
                                                    return Err(err.into());
                                                },
                                            },
                                        }
                                    } else {
                                        runtime.set_gp_register(GpRegister::a0, -libc::ENOENT as i64 as u64);
                                    }
                                },
                            }
                        },
                        syscalls::openat => {
                            //let a0 = runtime.get_gp_register(GpRegister::a0);
                            let a1 = runtime.get_gp_register(GpRegister::a1);
                            //let a2 = runtime.get_gp_register(GpRegister::a2);
                            //let a3 = runtime.get_gp_register(GpRegister::a3);
                            let pathname = runtime.load_string(a1)?;

                            match pathname {
                                b"file" => {
                                    let fd = self.kernel.open_fuzz_input(fuzz_input.len())?;
                                    runtime.set_gp_register(GpRegister::a0, fd as u64);
                                },
                                _ => unreachable!(),
                                /*
                                Ok(pathname) => {
                                    let fd = self.kernel.openat(a0 as i32, pathname, a2 as i32, a3 as i32)?;
                                    runtime.set_gp_register(GpRegister::a0, fd as u64);
                                },
                                */
                            }
                        },
                        syscalls::readv => {
                            let fd = runtime.get_gp_register(GpRegister::a0) as i32;
                            let iov = runtime.get_gp_register(GpRegister::a1);
                            let iovcnt = runtime.get_gp_register(GpRegister::a2);

                            let mut ret = 0;

                            for i in 0..iovcnt {
                                let iov = iov + i * 16;
                                let iov_base = runtime.load_dword(iov)? as VAddr;
                                let iov_len = runtime.load_dword(iov + 8)? as usize;
                                let data = if self.kernel.is_fuzz_input(fd) {
                                    let r = self.kernel.read_fuzz_input(fd, iov_len)?;
                                    &fuzz_input[r]
                                } else {
                                    self.kernel.read(fd, iov_len)?
                                };

                                runtime.store_slice(iov_base, data)?;
                                ret += data.len();

                                if data.len() < iov_len {
                                    break;
                                }
                            }

                            runtime.set_gp_register(GpRegister::a0, ret as u64);
                        },
                        syscalls::lseek => {
                            let fd = runtime.get_gp_register(GpRegister::a0);
                            let offset = runtime.get_gp_register(GpRegister::a1);
                            let whence = runtime.get_gp_register(GpRegister::a2);

                            let offset = self.kernel.seek(fd as i32, offset as i64, whence as i32)?;

                            runtime.set_gp_register(GpRegister::a0, offset as u64);
                        },
                        syscalls::read => {
                            let fd = runtime.get_gp_register(GpRegister::a0) as i32;
                            let buf = runtime.get_gp_register(GpRegister::a1);
                            let len = runtime.get_gp_register(GpRegister::a2) as usize;

                            let data = if self.kernel.is_fuzz_input(fd) {
                                let r = self.kernel.read_fuzz_input(fd, len)?;
                                &fuzz_input[r]
                            } else {
                                self.kernel.read(fd, len)?
                            };
                            runtime.store_slice(buf, data)?;

                            runtime.set_gp_register(GpRegister::a0, data.len() as u64);
                        },
                        syscalls::close => {
                            let fd = runtime.get_gp_register(GpRegister::a0);
                            self.kernel.close(fd as i32)?;
                            runtime.set_gp_register(GpRegister::a0, 0);
                        },
                        syscalls::readlinkat => {
                            let fd = runtime.get_gp_register(GpRegister::a0) as i32;
                            let a1 = runtime.get_gp_register(GpRegister::a1);
                            let path = runtime.load_string(a1)?;
                            debug_assert_eq!(fd, libc::AT_FDCWD);

                            match path {
                                b"file" => {
                                    runtime.set_gp_register(GpRegister::a0, -libc::EINVAL as i64 as u64);
                                },
                                _ => {
                                    return Err(ClangRuntimeFault::InternalError(format!("readlinkat: {:?}", path)));
                                },
                            }
                        },
                        syscalls::getcwd => {
                            let buf = runtime.get_gp_register(GpRegister::a0) as VAddr;
                            let size = runtime.get_gp_register(GpRegister::a1) as usize;
                            let cwd = b"/\x00";
                            let ret_size = std::cmp::min(size, cwd.len());
                            runtime.store_slice(buf, &cwd[..ret_size])?;
                            runtime.set_gp_register(GpRegister::a0, ret_size as u64);
                        },
                        _ => {
                            return Err(ClangRuntimeFault::InternalError(format!("syscall {}", a7)));
                        },
                    }
                },
                EVENT_ID_MALLOC => {
                    let size = runtime.get_gp_register(GpRegister::a0) as usize;
                    let addr = match runtime.dynstore_allocate(size) {
                        Ok(addr) => addr,
                        Err(ClangRuntimeFault::HeapError(HeapError::OutOfMemory(_))) => 0,
                        Err(e) => {
                            return Err(e);
                        },
                    };
                    runtime.set_gp_register(GpRegister::a0, addr);
                },
                EVENT_ID_FREE => {
                    let addr = runtime.get_gp_register(GpRegister::a0);
                    runtime.dynstore_deallocate(addr)?;
                },
                EVENT_ID_REALLOC => {
                    let chunk = runtime.get_gp_register(GpRegister::a0) as VAddr;
                    let size = runtime.get_gp_register(GpRegister::a1) as usize;

                    if size == 0 {
                        runtime.dynstore_deallocate(chunk)?;
                        runtime.set_gp_register(GpRegister::a0, 0);
                    } else if chunk == 0 {
                        let addr = match runtime.dynstore_allocate(size) {
                            Ok(addr) => addr,
                            Err(ClangRuntimeFault::HeapError(HeapError::OutOfMemory(_))) => 0,
                            Err(e) => {
                                return Err(e);
                            },
                        };
                        runtime.set_gp_register(GpRegister::a0, addr);
                    } else {
                        let new_chunk = match runtime.dynstore_reallocate(chunk, size) {
                            Ok(addr) => addr,
                            Err(ClangRuntimeFault::HeapError(HeapError::OutOfMemory(_))) => 0,
                            Err(e) => {
                                return Err(e);
                            },
                        };
                        runtime.set_gp_register(GpRegister::a0, new_chunk);
                    }
                },
                EVENT_ID_CALLOC => {
                    let a = runtime.get_gp_register(GpRegister::a0) as usize;
                    let b = runtime.get_gp_register(GpRegister::a1) as usize;
                    let size = a
                        .checked_mul(b)
                        .ok_or_else(|| ClangRuntimeFault::InternalError(format!("calloc overflow: {} * {}", a, b)))?;
                    let addr = match runtime.dynstore_allocate(size) {
                        Ok(addr) => addr,
                        Err(ClangRuntimeFault::HeapError(HeapError::OutOfMemory(_))) => 0,
                        Err(e) => {
                            return Err(e);
                        },
                    };

                    if addr > 0 {
                        for perm in runtime.permissions_mut(addr, size)? {
                            *perm &= !PERM_UNINIT;
                        }
                    }

                    runtime.set_gp_register(GpRegister::a0, addr);
                },
                EVENT_ID_TAKE_SNAPSHOT => {
                    runtime.take_snapshot(0);
                    num_instrs = 0;
                },
                EVENT_ID_RESTORE_SNAPSHOT => {
                    break;
                },
                _ => unreachable!(),
            }

            num_instrs += runtime.get_executed_instructions();
        }

        num_instrs += runtime.get_executed_instructions();
        Ok(num_instrs)
    }
}

impl<'a, S, OT> UsesState for SquidExecutor<'a, S, OT>
where
    S: State,
    OT: ObserversTuple<S>,
{
    type State = S;
}

impl<'a, S, OT, EM, Z> Executor<EM, Z> for SquidExecutor<'a, S, OT>
where
    S: State + HasExecutions,
    S: UsesInput<Input = BytesInput>,
    OT: ObserversTuple<S>,
    EM: UsesState<State = Self::State>,
    Z: UsesState<State = Self::State>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &BytesInput,
    ) -> Result<ExitKind, Error> {
        *state.executions_mut() += 1;

        self.kernel.restore_snapshot(0);
        let _ = self.runtime.restore_snapshot(0);

        let start = std::time::Instant::now();

        match self.run(input.bytes()) {
            Ok(num_instrs) => {
                let secs = start.elapsed().as_secs_f64();
                let observer = self.observers.get_mut(&self.handle).unwrap();
                observer.update(num_instrs, secs);
                Ok(ExitKind::Ok)
            },
            Err(_e) => {
                #[cfg(debug_assertions)]
                println!("{}", _e);

                Ok(ExitKind::Crash)
            },
        }
    }
}

impl<'a, S, OT> UsesObservers for SquidExecutor<'a, S, OT>
where
    S: State,
    OT: ObserversTuple<S>,
{
    type Observers = OT;
}

impl<'a, S, OT> HasObservers for SquidExecutor<'a, S, OT>
where
    S: State,
    OT: ObserversTuple<S>,
{
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        (&self.observers).into()
    }

    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        (&mut self.observers).into()
    }
}

use std::time::Duration;

use serde::{
    Deserialize,
    Serialize,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SquidObserver {
    name: Cow<'static, str>,
    last_runtime: Option<Duration>,
    total_instrs: f64,
    total_secs: f64,
}

impl SquidObserver {
    fn new(name: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            last_runtime: None,
            total_instrs: 0.0,
            total_secs: 0.0,
        }
    }

    fn update(&mut self, instrs: usize, secs: f64) {
        const GHZ: u64 = 2;
        self.last_runtime = Some(Duration::from_nanos(instrs as u64 / GHZ));
        self.total_instrs += instrs as f64;
        self.total_secs += secs;
    }

    fn last_runtime(&self) -> Option<&Duration> {
        self.last_runtime.as_ref()
    }

    fn instr_per_sec(&self) -> f64 {
        self.total_instrs / self.total_secs
    }
}

impl<S> Observer<S> for SquidObserver
where
    S: UsesInput,
{
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn pre_exec(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) -> Result<(), Error> {
        self.last_runtime = None;
        Ok(())
    }

    fn post_exec(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }

    fn pre_exec_child(&mut self, _state: &mut S, _input: &<S as UsesInput>::Input) -> Result<(), Error> {
        Ok(())
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for SquidObserver {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[inline]
fn within_window<const W: usize>(value: f64, base: f64) -> bool {
    value >= (base - W as f64) && value <= (base + W as f64)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SquidFeedback {
    last_instr_per_sec: f64,
    handle: Handle<SquidObserver>,
}

impl SquidFeedback {
    fn new(observer: &SquidObserver) -> Self {
        Self {
            last_instr_per_sec: 0.0,
            handle: observer.handle(),
        }
    }
}

impl<S> Feedback<S> for SquidFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        mgr: &mut EM,
        _input: &<S>::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let observer = observers.get(&self.handle).unwrap();
        let instr_per_sec = observer.instr_per_sec();

        if !within_window::<{ 10 * 1024 * 1024 }>(instr_per_sec, self.last_instr_per_sec) {
            mgr.fire(
                state,
                Event::UpdateUserStats {
                    name: "instr/sec".to_string().into(),
                    value: UserStats::new(UserStatsValue::Float(instr_per_sec), AggregatorOps::Sum),
                    phantom: PhantomData,
                },
            )?;
            self.last_instr_per_sec = instr_per_sec;
        }

        Ok(false)
    }

    fn append_metadata<EM, OT>(
        &mut self,
        _state: &mut S,
        _mgr: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<S::Input>,
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>,
        EM: EventFirer<State = S>,
    {
        let observer = observers.get(&self.handle).unwrap();
        *testcase.exec_time_mut() = observer.last_runtime().copied();
        Ok(())
    }
}

impl Named for SquidFeedback {
    fn name(&self) -> &Cow<'static, str> {
        &Cow::Borrowed("SquidFeedback")
    }
}

#[derive(clap::Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Subcommand,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    Fuzz {
        #[arg(long)]
        riscv_binaries: String,

        #[arg(long)]
        native_binary: Option<String>,

        #[arg(long, default_value_t = String::from("0"))]
        cores: String,

        #[arg(long, default_value_t = 1)]
        num_exploitation: usize,

        #[arg(long)]
        corpus: String,

        #[arg(long)]
        output: String,
    },

    Replay {
        #[arg(long)]
        binaries: String,

        #[arg(long)]
        file: String,

        #[arg(long, default_value_t = false)]
        breakpoints: bool,
    },
}

fn assign_cores(cores: &[CoreId], mut num_exploitation: usize) -> Vec<CoreId> {
    num_exploitation = std::cmp::min(num_exploitation, cores.len());
    cores[0..num_exploitation].to_vec()
}

fn pick_exploit_powerschedule(core: usize) -> PowerSchedule {
    if core % 2 == 0 {
        PowerSchedule::EXPLOIT
    } else {
        PowerSchedule::FAST
    }
}

fn pick_explore_powerschedule(core: usize) -> PowerSchedule {
    if core % 2 == 0 {
        PowerSchedule::EXPLORE
    } else {
        PowerSchedule::FAST
    }
}

fn fuzz(
    riscv_binaries: String,
    native_binary: Option<String>,
    cores: String,
    num_exploitation: usize,
    corpus: String,
    output: String,
) -> Result<(), Error> {
    let cores = Cores::from_cmdline(&cores).unwrap();
    let exploitation_cores = assign_cores(&cores.ids, num_exploitation);
    let native_binary = if exploitation_cores.len() < cores.ids.len() {
        native_binary.expect("Must supply native binary for that")
    } else {
        String::new()
    };

    let _ = std::fs::create_dir_all(&output);
    let mut runtime = create_runtime(&riscv_binaries, &output, false);

    let mut run_exploit = |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _, _>, core_id: CoreId| {
        let powerschedule = pick_exploit_powerschedule(core_id.0);
        println!("Running exploit instance on core #{} with powerschedule {:?}", core_id.0, powerschedule);

        let coverage_map = get_coverage_map(&mut runtime);
        let map_observer =
            HitcountsMapObserver::new(StdMapObserver::from_mut_slice("hitcounters", coverage_map)).track_indices();
        let squid_observer = SquidObserver::new("instructions");

        let map_feedback = MaxMapFeedback::new(&map_observer);
        let squid_feedback = SquidFeedback::new(&squid_observer);

        let calibration_stage = CalibrationStage::new(&map_feedback);

        let mut feedback = feedback_or!(map_feedback, squid_feedback);

        let mut objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

        let mut state = if let Some(state) = state {
            state
        } else {
            StdState::new(
                StdRand::with_seed(current_nanos().rotate_right(core_id.0 as u32)),
                CachedOnDiskCorpus::<BytesInput>::new(format!("{}/queue", &output), 128)?,
                OnDiskCorpus::new(format!("{}/crashes", &output))?,
                &mut feedback,
                &mut objective,
            )?
        };

        let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)?;
        let mutational_stage = StdPowerMutationalStage::new(mutator);

        // For perf measurements:
        //let mutator = libafl::prelude::NopMutator::new(libafl::prelude::MutationResult::Mutated);
        //let mutational_stage = libafl::prelude::StdMutationalStage::new(mutator);

        let scheduler = IndexesLenTimeMinimizerScheduler::new(
            &map_observer,
            StdWeightedScheduler::with_schedule(&mut state, &map_observer, Some(powerschedule)),
        );

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let mut executor =
            SquidExecutor::new(squid_observer.handle(), tuple_list!(squid_observer, map_observer), &mut runtime);

        let mut stages = tuple_list!(calibration_stage, mutational_stage);

        if state.must_load_initial_inputs() {
            state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from(&corpus)])?;
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

        Ok(())
    };
    let run_explore = |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _, _>, core_id: CoreId| {
        let powerschedule = pick_explore_powerschedule(core_id.0);
        println!("Running exploration instance on core #{} with powerschedule {:?}", core_id.0, powerschedule);

        const MAP_SIZE: usize = 65536;
        let mut shmem_provider = UnixShMemProvider::new().unwrap();
        let mut shmem = shmem_provider.new_shmem(MAP_SIZE).unwrap();
        shmem.write_to_env("__AFL_SHM_ID").unwrap();
        let shmem_buf = shmem.as_slice_mut();
        std::env::set_var("AFL_MAP_SIZE", format!("{}", MAP_SIZE));

        let edges_observer =
            unsafe { HitcountsMapObserver::new(StdMapObserver::new("shared_mem", shmem_buf)).track_indices() };
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new(&edges_observer);
        let calibration = CalibrationStage::new(&map_feedback);

        let mut feedback = feedback_or!(map_feedback, TimeFeedback::new(&time_observer));

        let mut objective = CrashFeedback::new();

        let mut state = if let Some(state) = state {
            state
        } else {
            StdState::new(
                StdRand::with_seed(current_nanos().rotate_right(core_id.0 as u32)),
                CachedOnDiskCorpus::<BytesInput>::new(format!("{}/queue", &output), 128)?,
                OnDiskCorpus::new(format!("{}/crashes", &output))?,
                &mut feedback,
                &mut objective,
            )?
        };

        let mutator = StdMOptMutator::new(&mut state, havoc_mutations(), 7, 5)?;
        let power = StdPowerMutationalStage::new(mutator);

        // For perf measurements:
        //let mutator = libafl::prelude::NopMutator::new(libafl::prelude::MutationResult::Mutated);
        //let power = libafl::prelude::StdMutationalStage::new(mutator);

        let scheduler = IndexesLenTimeMinimizerScheduler::new(
            &edges_observer,
            StdWeightedScheduler::with_schedule(&mut state, &edges_observer, Some(powerschedule)),
        );

        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);
        let mut executor = ForkserverExecutor::builder()
            .program(&native_binary)
            .debug_child(cfg!(debug_assertions))
            .shmem_provider(&mut shmem_provider)
            .parse_afl_cmdline(["-W", "-a", "@@"])
            .coverage_map_size(MAP_SIZE)
            .timeout(Duration::from_millis(5000))
            .is_persistent(false)
            .build_dynamic_map(edges_observer, tuple_list!(time_observer))
            .unwrap();

        let mut stages = tuple_list!(calibration, power);

        if state.must_load_initial_inputs() {
            state.load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from(&corpus)])?;
        }

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

        Ok(())
    };
    let mut run_client = |state: Option<_>, mgr: LlmpRestartingEventManager<_, _, _>, core_id: CoreId| {
        if exploitation_cores.contains(&core_id) {
            run_exploit(state, mgr, core_id)
        } else {
            run_explore(state, mgr, core_id)
        }
    };
    let mut last_update = current_time();
    let monitor = OnDiskJSONMonitor::new(
        format!("{}/stats.jsonl", &output),
        MultiMonitor::new(|s| println!("{}", s)),
        move |_| {
            let now = current_time();
            if (now - last_update).as_secs() >= 60 {
                last_update = now;
                true
            } else {
                false
            }
        },
    );
    let shmem_provider = StdShMemProvider::new()?;

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::AlwaysUnique)
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .build()
        .launch()
    {
        Err(Error::ShuttingDown) | Ok(()) => Ok(()),
        e => e,
    }
}

fn replay(binaries: String, file: String, breakpoints: bool) -> Result<(), Error> {
    let input = BytesInput::from_file(file)?;

    let monitor = NopMonitor::new();
    let mut mgr = SimpleEventManager::new(monitor);

    let squid_observer = SquidObserver::new("instructions");

    let mut feedback = SquidFeedback::new(&squid_observer);
    let mut objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::<BytesInput>::new(),
        InMemoryCorpus::<BytesInput>::new(),
        &mut feedback,
        &mut objective,
    )?;

    let scheduler = StdScheduler::new();

    let mut fuzzer: StdFuzzer<_, _, _, (SquidObserver, ())> = StdFuzzer::new(scheduler, feedback, objective);

    let mut runtime = create_runtime(&binaries, "/tmp", breakpoints);
    let mut executor = SquidExecutor::new(squid_observer.handle(), tuple_list!(squid_observer), &mut runtime);

    let status = executor.run_target(&mut fuzzer, &mut state, &mut mgr, &input)?;
    println!("{:?}", status);

    Ok(())
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    match args.command {
        Subcommand::Fuzz {
            riscv_binaries,
            native_binary,
            cores,
            num_exploitation,
            corpus,
            output,
        } => fuzz(riscv_binaries, native_binary, cores, num_exploitation, corpus, output),
        Subcommand::Replay {
            binaries,
            file,
            breakpoints,
        } => replay(binaries, file, breakpoints),
    }
}
