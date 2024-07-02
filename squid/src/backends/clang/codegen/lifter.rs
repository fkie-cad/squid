#![allow(clippy::result_large_err)]

use std::{
    fs::File,
    io::{
        BufWriter,
        Read,
        Write,
    },
    path::PathBuf,
    process::Command,
    time::Instant,
};

use thiserror::Error;

use crate::{
    backends::clang::{
        address::{
            AddressSpace,
            POINTER_CODE_MASK,
            POINTER_CODE_SHIFT,
            POINTER_TAG_CODE,
            POINTER_TAG_MASK,
            POINTER_TAG_SHIFT,
        },
        codegen::subcfg::{
            split_into_subgraphs,
            SubGraph,
        },
        memory::SNAPSHOT_REGION_SIZE,
        perms,
        runtime::broadcast_perm,
        AOTExecutor,
        AOTReturnCode,
        Memory,
        VariableStorage,
    },
    frontend::{
        ao::{
            engine,
            Comparison,
            Edge,
            Half,
            Op,
            Register,
            Signedness,
            Var,
            VarType,
            CFG,
        },
        ChunkContent,
        HasId,
        Id,
        ProcessImage,
        VAddr,
    },
    logger::Logger,
    riscv::{
        ieee754::NAN_BOX,
        register::GpRegister,
    },
};

/// This error type represents everything that can go wrong when generating C code.
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum CLifterError {
    #[error("The engine exploded: {0}")]
    Engine(#[from] engine::EngineError),

    #[error("Could not write to source file: {0}")]
    IOError(#[from] std::io::Error),

    #[error("The compiler had an error")]
    CompilationFailed,
}

pub(crate) struct CLifter {
    out_source: PathBuf,
    out_binary: PathBuf,
    basic_block_table_size: usize,
    update_pc: bool,
    update_last_instr: bool,
    timeout: usize,
    count_instructions: bool,
    config_hash: u64,
    num_functions: usize,
    uninit_stack: bool,
    allow_div_by_zero: bool,
}

impl CLifter {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        out_source: PathBuf,
        update_pc: bool,
        update_last_instr: bool,
        timeout: usize,
        count_instructions: bool,
        config_hash: u64,
        basic_block_table_size: usize,
        uninit_stack: bool,
        allow_div_by_zero: bool,
    ) -> Self {
        let mut out_binary = out_source.clone();
        out_binary.set_extension("so");

        Self {
            out_source,
            out_binary,
            basic_block_table_size,
            update_pc,
            update_last_instr,
            timeout,
            count_instructions,
            config_hash,
            num_functions: 0,
            uninit_stack,
            allow_div_by_zero,
        }
    }

    fn read_config_hash(&self) -> u64 {
        let mut file = File::open(&self.out_source).unwrap();
        let mut line = [0u8; 2 + 7 + 16 + 1];

        if file.read(&mut line).unwrap() != line.len() {
            return 0;
        }

        if !line.starts_with(b"//config:") || line[2 + 7 + 16] != b'\n' {
            return 0;
        }

        let hash = std::str::from_utf8(&line[2 + 7..2 + 7 + 16]).unwrap();

        u64::from_str_radix(hash, 16).unwrap_or(0)
    }

    fn needs_recompilation(&self) -> bool {
        if !self.out_source.exists() || !self.out_binary.exists() {
            return true;
        }

        self.read_config_hash() != self.config_hash
    }

    pub(crate) fn lift(
        &mut self,
        image: &ProcessImage,
        memory: &Memory,
        varstore: &VariableStorage,
        logger: &Logger,
        cflags: &[String],
        cc: &str,
    ) -> Result<AOTExecutor, CLifterError> {
        logger.debug(format!("Config hash: {:016x}", self.config_hash));

        if self.needs_recompilation() {
            self.generate_c_code(image, memory, varstore, logger)?;
            self.compile_code(cc, cflags, logger)?;
        } else {
            logger.info(format!("Reusing existing {}", self.out_binary.display()));
        }

        Ok(AOTExecutor::new(&self.out_binary))
    }

    fn compile_code(&mut self, cc: &str, cflags: &[String], logger: &Logger) -> Result<(), CLifterError> {
        let mut args = vec!["-o", self.out_binary.to_str().unwrap(), "-fPIC", "-shared", "-fvisibility=hidden", "-nostdlib"];
        for cflag in cflags {
            args.push(cflag.as_ref());
        }
        args.push(self.out_source.to_str().unwrap());

        logger.info(format!("Invoking {} {}", cc, args.join(" ")));

        let start = Instant::now();

        let mut child = Command::new(cc).args(args).spawn().unwrap();
        let status = child.wait().unwrap();

        if !status.success() {
            return Err(CLifterError::CompilationFailed);
        }

        let mut time = (Instant::now() - start).as_secs();
        let hours = time / 3600;
        time %= 3600;
        let minutes = time / 60;
        time %= 60;
        logger.info(format!("Compilation took {}h {}m {}s", hours, minutes, time));

        Ok(())
    }

    fn generate_c_code(&mut self, image: &ProcessImage, memory: &Memory, varstore: &VariableStorage, logger: &Logger) -> Result<(), CLifterError> {
        logger.info(format!("Generating {}", self.out_source.display()));

        /* First collect subgraphs */
        let mut subgraphs = Vec::new();
        for elf in image.iter_elfs() {
            for section in elf.iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if let ChunkContent::Code(func) = chunk.content() {
                            let g = split_into_subgraphs(func);
                            self.num_functions += g.len();
                            subgraphs.push(g);
                        }
                    }
                }
            }
        }

        /* Then, generate source */
        let mut out_file = BufWriter::new(File::create(&self.out_source).unwrap());
        self.emit_config_hash(&mut out_file)?;
        self.emit_header(&mut out_file)?;
        self.emit_types(&mut out_file, memory)?;
        self.emit_function_table(&mut out_file, image, &subgraphs)?;
        self.emit_faults(&mut out_file)?;
        self.emit_subroutines(&mut out_file, memory)?;
        self.emit_store_memory(&mut out_file, memory)?;
        self.emit_load_memory(&mut out_file, memory)?;
        self.emit_entrypoint(&mut out_file)?;

        let mut subgraphs_iter = subgraphs.iter();

        for elf in image.iter_elfs() {
            for section in elf.iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if let ChunkContent::Code(func) = chunk.content() {
                            let subgraphs = subgraphs_iter.next().unwrap();

                            for subgraph in subgraphs {
                                self.emit_subgraph(&mut out_file, func.cfg(), subgraph, varstore)?;
                            }
                        }
                    }
                }
            }
        }

        assert!(subgraphs_iter.next().is_none());

        writeln!(&mut out_file)?;
        out_file.flush()?;
        Ok(())
    }

    fn emit_config_hash(&mut self, out_file: &mut BufWriter<File>) -> Result<(), CLifterError> {
        writeln!(out_file, "//config:{:016x}", self.config_hash)?;
        Ok(())
    }

    fn emit_header(&mut self, out_file: &mut BufWriter<File>) -> Result<(), CLifterError> {
        /* Check C compiler */
        writeln!(out_file, "#ifndef __clang__")?;
        writeln!(out_file, "#error \"This can only be compiled with clang\"")?;
        writeln!(out_file, "#endif")?;

        /* Ignore unused stuff */
        writeln!(out_file, "#pragma clang diagnostic ignored \"-Wunused-variable\"")?;
        writeln!(out_file, "#pragma clang diagnostic ignored \"-Wunused-parameter\"")?;
        writeln!(out_file, "#pragma clang diagnostic ignored \"-Wunused-label\"")?;
        writeln!(out_file, "#pragma clang diagnostic push")?;
        writeln!(out_file, "#pragma clang diagnostic ignored \"-Wunused-function\"")?;

        /* Used headers */
        writeln!(out_file, "#include <stddef.h>")?;
        writeln!(out_file, "#include <stdint.h>")?;

        /* Used macros */
        writeln!(out_file, "#define UNLIKELY(x) __builtin_expect(!!(x), 0)")?;
        writeln!(out_file, "#define LIKELY(x) __builtin_expect(!!(x), 1)")?;

        writeln!(out_file, "#define POINTER_TAG_SHIFT {}", POINTER_TAG_SHIFT)?;
        writeln!(out_file, "#define POINTER_BB_MASK  {:#x}ULL", !(POINTER_TAG_MASK | POINTER_CODE_MASK))?;
        writeln!(out_file, "#define POINTER_IDX_MASK  {:#x}ULL", POINTER_CODE_MASK)?;
        writeln!(out_file, "#define POINTER_INDEX_SHIFT  {}", POINTER_CODE_SHIFT)?;
        writeln!(out_file, "#define POINTER_TAG_CODE {}ULL", POINTER_TAG_CODE >> POINTER_TAG_SHIFT)?;
        writeln!(out_file, "#define TAG_BB_ADDRESS(address, func) (address | ( ((uint64_t)(void*) func) - ((uint64_t)(void*) run) ))")?;

        writeln!(out_file, "#define REGION_BITS {}", SNAPSHOT_REGION_SIZE.ilog2())?;
        writeln!(out_file, "#define REINTERPRET(T, x) ( *((T*)(&(x))) )")?;
        writeln!(out_file, "#define MIN(x, y) ( ((x) < (y)) ? (x) : (y) )")?;
        writeln!(out_file, "#define MAX(x, y) ( ((x) > (y)) ? (x) : (y) )")?;
        writeln!(out_file, "#define EXTEND(T1, T2, x) ( (T2) ((T1)(x)) )")?;
        writeln!(out_file, "#define CONVERT(T, x) ( (T)(x) )")?;

        /* Types needed by basic block functions */
        writeln!(out_file, "typedef __int128 int128_t;")?;
        writeln!(out_file, "typedef unsigned __int128 uint128_t;")?;
        writeln!(out_file, "typedef struct _Context Context;")?;
        writeln!(out_file, "typedef void*(*BasicBlockFn)(Context* ctx, uint64_t* next_pc, uint64_t* num_instructions);")?;

        Ok(())
    }

    fn emit_types(&mut self, out_file: &mut BufWriter<File>, memory: &Memory) -> Result<(), CLifterError> {
        /* Event channel */
        writeln!(out_file, "typedef struct __attribute__((packed)) {{ uint64_t length; uint64_t data[]; }} EventChannel;")?;

        /* AOT return codes */
        writeln!(out_file, "enum AOTReturnCode {{")?;
        writeln!(out_file, "    RETURN_EVENT = {},", AOTReturnCode::Event as u32)?;
        writeln!(out_file, "    RETURN_INVALID_STATE = {},", AOTReturnCode::InvalidState as u32)?;
        writeln!(out_file, "    RETURN_INVALID_JUMP_TARGET = {},", AOTReturnCode::InvalidJumpTarget as u32)?;
        writeln!(out_file, "    RETURN_INVALID_READ = {},", AOTReturnCode::InvalidRead as u32)?;
        writeln!(out_file, "    RETURN_UNINIT_READ = {},", AOTReturnCode::UninitializedRead as u32)?;
        writeln!(out_file, "    RETURN_END = {},", AOTReturnCode::End as u32)?;
        writeln!(out_file, "    RETURN_INVALID_WRITE = {},", AOTReturnCode::InvalidWrite as u32)?;
        writeln!(out_file, "    RETURN_INVALID_EVENT_CHANNEL = {},", AOTReturnCode::InvalidEventChannel as u32)?;
        writeln!(out_file, "    RETURN_DIV_BY_ZERO = {},", AOTReturnCode::DivByZero as u32)?;
        writeln!(out_file, "    RETURN_TIMEOUT = {},", AOTReturnCode::Timeout as u32)?;
        writeln!(out_file, "}};")?;

        /* Return buffer */
        writeln!(out_file, "typedef struct {{ uint32_t code; uint64_t arg0; uint64_t arg1; uint64_t instr_count; }} ReturnBuffer;")?;

        /* Registers */
        writeln!(out_file, "typedef struct __attribute__((packed)) {{ uint64_t gp[32]; uint64_t pc; uint64_t current_addr; double fp[32]; uint64_t fcsr; }} Registers;")?;
        writeln!(out_file, "typedef struct __attribute__((packed)) {{ uint64_t gp[32]; uint64_t pc; uint64_t current_addr; }} LocalRegisters;")?;
        writeln!(out_file, "static LocalRegisters local_registers;")?;

        /* Word sizes */
        writeln!(out_file, "typedef uint8_t Byte;")?;
        writeln!(out_file, "typedef uint16_t Hword;")?;
        writeln!(out_file, "typedef uint32_t Word;")?;
        writeln!(out_file, "typedef uint64_t Dword;")?;

        /* Memory types */
        writeln!(out_file, "#pragma clang diagnostic push")?;
        writeln!(out_file, "#pragma clang diagnostic ignored \"-Wflexible-array-extensions\"")?;
        writeln!(out_file, "#pragma clang diagnostic ignored \"-Wzero-length-array\"")?;

        writeln!(out_file, "typedef struct __attribute__((packed)) {{ uint64_t size; uint64_t regions[]; }} SnapshotStack;")?;

        let content_size = memory.offset_perms();
        let perms_size = memory.offset_dirty_bits() - memory.offset_perms();
        let bits_size = memory.offset_dirty_stack() - memory.offset_dirty_bits();
        writeln!(
            out_file,
            "typedef struct __attribute__((packed)) {{ uint8_t content[{}]; uint8_t perms[{}]; uint8_t dirty_bits[{}]; SnapshotStack dirty_stack; }} Memory;",
            content_size, perms_size, bits_size
        )?;

        writeln!(out_file, "#pragma clang diagnostic pop")?;

        writeln!(out_file, "struct _Context {{ Memory* memory; EventChannel* event_channel; ReturnBuffer* return_buf; uint64_t* static_vars; Registers* registers; }};")?;

        writeln!(out_file, "enum OpSize {{ BYTE_SIZE = 1, HWORD_SIZE = 2, WORD_SIZE = 4, DWORD_SIZE = 8, }};")?;
        writeln!(out_file, "uint64_t run (void*, void*, void*, void*, void*);")?;

        Ok(())
    }

    fn emit_function_table(&mut self, out_file: &mut BufWriter<File>, image: &ProcessImage, subgraphs: &[Vec<SubGraph>]) -> Result<(), CLifterError> {
        /* Forward declarations of basic block functions */
        let mut subgraphs_iter = subgraphs.iter();

        for elf in image.iter_elfs() {
            for section in elf.iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if let ChunkContent::Code(func) = chunk.content() {
                            let subgraphs = subgraphs_iter.next().unwrap();

                            for subgraph in subgraphs {
                                let bb = func.cfg().basic_block(subgraph.entry()).unwrap();
                                write!(out_file, "static void* basic_block_{:#x} (Context*, uint64_t*, uint64_t*);", bb.vaddr().unwrap())?;
                            }
                        }
                    }
                }
            }
        }

        writeln!(out_file)?;

        assert!(subgraphs_iter.next().is_none());

        /* Construct function table */
        let mut subgraphs_iter = subgraphs.iter();

        write!(out_file, "static BasicBlockFn basic_block_table[{}] = {{", self.basic_block_table_size)?;

        for elf in image.iter_elfs() {
            for section in elf.iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if let ChunkContent::Code(func) = chunk.content() {
                            let subgraphs = subgraphs_iter.next().unwrap();
                            let mut entries = Vec::new();

                            for subgraph in subgraphs {
                                entries.push(subgraph.entry());
                            }

                            for bb in func.cfg().iter_basic_blocks() {
                                if entries.contains(&bb.id()) {
                                    write!(out_file, "basic_block_{:#x},", bb.vaddr().unwrap())?;
                                } else {
                                    write!(out_file, "NULL,")?;
                                }
                            }
                        }
                    }
                }
            }
        }

        writeln!(out_file, "}};")?;
        assert!(subgraphs_iter.next().is_none());

        Ok(())
    }

    fn emit_faults(&mut self, out_file: &mut BufWriter<File>) -> Result<(), CLifterError> {
        writeln!(
            out_file,
            "
static inline BasicBlockFn fault_end (Context* ctx) {{
    ctx->return_buf->code = RETURN_END;
    return NULL;
}}

static inline BasicBlockFn fault_invalid_jump_target (Context* ctx, uint64_t address) {{
    ReturnBuffer* return_buf = ctx->return_buf;
    return_buf->code = RETURN_INVALID_JUMP_TARGET;
    return_buf->arg0 = address;
    return NULL;
}}

static inline BasicBlockFn fault_invalid_write (Context* ctx, uint64_t address, enum OpSize size) {{
    ReturnBuffer* return_buf = ctx->return_buf;
    return_buf->code = RETURN_INVALID_WRITE;
    return_buf->arg0 = address;
    return_buf->arg1 = size;
    return NULL;
}}

static inline BasicBlockFn fault_invalid_read (Context* ctx, uint64_t address, enum OpSize size) {{
    ReturnBuffer* return_buf = ctx->return_buf;
    return_buf->arg0 = address;
    return_buf->arg1 = size;
    return NULL;
}}

static inline BasicBlockFn fault_invalid_event_channel (Context* ctx, unsigned int requested_size, uint64_t actual_size) {{
    ReturnBuffer* return_buf = ctx->return_buf;
    return_buf->code = RETURN_INVALID_EVENT_CHANNEL;
    return_buf->arg0 = requested_size;
    return_buf->arg1 = actual_size;
    return NULL;
}}

static inline BasicBlockFn fault_div_by_zero (Context* ctx) {{
    ReturnBuffer* return_buf = ctx->return_buf;
    return_buf->code = RETURN_DIV_BY_ZERO;
    return NULL;
}}"
        )?;

        Ok(())
    }

    fn emit_subroutines(&mut self, out_file: &mut BufWriter<File>, memory: &Memory) -> Result<(), CLifterError> {
        writeln!(
            out_file,
            "
static BasicBlockFn lookup_basic_block_table (Context* ctx, uint64_t address) {{
    uint64_t tag = address >> POINTER_TAG_SHIFT;

    if (UNLIKELY(tag != POINTER_TAG_CODE)) {{
        return fault_invalid_jump_target(ctx, address);
    }}
    
    uint64_t bb = address & POINTER_BB_MASK;
    if (LIKELY(bb)) {{
        return (BasicBlockFn) (bb + (uint64_t)(void*)run);
    }}
    
    uint64_t offset = (address & POINTER_IDX_MASK) >> POINTER_INDEX_SHIFT;

    if (UNLIKELY(offset >= {0}ULL)) {{
        return fault_invalid_jump_target(ctx, address);
    }}

    BasicBlockFn ret = basic_block_table[offset];
    
    if (UNLIKELY(!ret)) {{
        return fault_invalid_jump_target(ctx, address);
    }}
    
    return ret;
}}

static BasicBlockFn lookup_pc (Context* ctx) {{
    uint64_t pc = local_registers.pc;

    if (UNLIKELY(!pc)) {{
        return fault_end(ctx);
    }}

    return lookup_basic_block_table(ctx, pc);
}}

static void mark_offset_dirty (Memory* memory, uint64_t offset, unsigned int size) {{
    uint8_t* bits = &memory->dirty_bits[0];
    SnapshotStack* stack = &memory->dirty_stack;
    uint64_t region_index = offset >> REGION_BITS;
    uint64_t idx = region_index / 8;
    uint8_t bit = 1 << (region_index % 8);

    uint8_t entry = bits[idx];

    if (LIKELY(entry & bit)) {{
        return;
    }}

    bits[idx] |= bit;

    uint64_t stack_size = stack->size;
    stack->size = stack_size + 1;
    stack->regions[stack_size] = region_index;

    /* Check if store overlaps regions */
    offset += size - 1;

    if (UNLIKELY((offset >> REGION_BITS) > region_index)) {{
        mark_offset_dirty(memory, offset, 1);
    }}
}}

static uint64_t classify32 (float value) {{
    uint64_t ret = 0;
    uint32_t bits = REINTERPRET(uint32_t, value);
    uint32_t sign = bits >> 31;
    
    if (__builtin_isnan(value)) {{
        unsigned int idx = 8 + ((bits >> 22) & 1);
        ret |= (1 << idx);
    }}
    
    if (__builtin_isinf(value)) {{
        if (sign) {{
            ret |= 1;
        }} else {{
            ret |= (1 << 7);
        }}
    }}
    
    if ((bits << 1) == 0) {{
        ret |= (1 << (4 - sign));
    }}
    
    if ((bits & 0x7f800000) == 0) {{
        if (sign) {{
            ret |= (1 << 2);
        }} else {{
            ret |= (1 << 5);
        }}
    }}
    
    if (sign) {{
        ret |= (1 << 1);
    }} else {{
        ret |= (1 << 6);
    }}
    
    return ret;
}}

static uint64_t classify64 (double value) {{
    uint64_t ret = 0;
    uint64_t bits = REINTERPRET(uint64_t, value);
    uint64_t sign = bits >> 63;
    
    if (__builtin_isnan(value)) {{
        unsigned int idx = 8 + ((bits >> 51) & 1);
        ret |= (1 << idx);
    }}
    
    if (__builtin_isinf(value)) {{
        if (sign) {{
            ret |= 1;
        }} else {{
            ret |= (1 << 7);
        }}
    }}
    
    if ((bits << 1) == 0) {{
        ret |= (1 << (4 - sign));
    }}
    
    if ((bits & 0x7ff0000000000000ULL) == 0) {{
        if (sign) {{
            ret |= (1 << 2);
        }} else {{
            ret |= (1 << 5);
        }}
    }}
    
    if (sign) {{
        ret |= (1 << 1);
    }} else {{
        ret |= (1 << 6);
    }}
    
    return ret;
}}

static void mark_stack_uninit (Memory* memory, uint64_t pre, uint64_t post) {{
    if (UNLIKELY(pre >= {1}ULL || post >= {1}ULL)) {{
        return;
    }}

    uint64_t lower = MIN(pre, post);
    uint64_t upper = MAX(pre, post);
    uint64_t size = upper - lower;

    uint8_t* cursor = &memory->perms[lower];

    for (uint64_t i = 0; i < size; ++i) {{
        cursor[i] |= {2};
    }}
}}

static inline __attribute__((always_inline)) uint64_t saturating_add64 (uint64_t a, uint64_t b) {{
    uint64_t c = a + b;
    if (c < a) c = -1LL;
    return c;
}}
",
            self.basic_block_table_size,
            memory.size(),
            perms::PERM_UNINIT,
        )?;

        Ok(())
    }

    fn emit_store_memory(&mut self, out_file: &mut BufWriter<File>, memory: &Memory) -> Result<(), CLifterError> {
        let mask_write_byte = perms::PERM_WRITE;
        let mask_clear_uninit_byte = !perms::PERM_UNINIT;

        let mask_write_hword = broadcast_perm::<u16>(perms::PERM_WRITE);
        let mask_clear_uninit_hword = broadcast_perm::<u16>(!perms::PERM_UNINIT);

        let mask_write_word = broadcast_perm::<u32>(perms::PERM_WRITE);
        let mask_clear_uninit_word = broadcast_perm::<u32>(!perms::PERM_UNINIT);

        let mask_write_dword = broadcast_perm::<u64>(perms::PERM_WRITE);
        let mask_clear_uninit_dword = broadcast_perm::<u64>(!perms::PERM_UNINIT);

        writeln!(
            out_file,
            "
static int store_memory_byte (Context* ctx, uint64_t address, uint64_t value) {{
    if (UNLIKELY(saturating_add64(address, sizeof(Byte)) > {0}ULL)) {{
        return 0;
    }}
    
    Memory* memory = ctx->memory;
    Byte* content = (Byte*) &memory->content[address];
    Byte* perms = (Byte*) &memory->perms[address];
    Byte perm_bits = *perms;

    if (UNLIKELY((perm_bits & {mask_write_byte:#x}U) != {mask_write_byte:#x}U)) {{
        return 0;
    }}

    perm_bits &= {mask_clear_uninit_byte:#x}U;
    *perms = perm_bits;
    *content = (Byte) value;

    mark_offset_dirty(memory, address, sizeof(Byte));
    return 1;
}}

static int store_memory_hword (Context* ctx, uint64_t address, uint64_t value) {{
    if (UNLIKELY(saturating_add64(address, sizeof(Hword)) > {0}ULL)) {{
        return 0;
    }}
    
    Memory* memory = ctx->memory;
    Hword* content = (Hword*) &memory->content[address];
    Hword* perms = (Hword*) &memory->perms[address];
    Hword perm_bits = *perms;

    if (UNLIKELY((perm_bits & {mask_write_hword:#x}U) != {mask_write_hword:#x}U)) {{
        return 0;
    }}

    perm_bits &= {mask_clear_uninit_hword:#x}U;
    *perms = perm_bits;
    *content = (Hword) value;

    mark_offset_dirty(memory, address, sizeof(Hword));
    return 1;
}}

static int store_memory_word (Context* ctx, uint64_t address, uint64_t value) {{
    if (UNLIKELY(saturating_add64(address, sizeof(Word)) > {0}ULL)) {{
        return 0;
    }}
    
    Memory* memory = ctx->memory;
    Word* content = (Word*) &memory->content[address];
    Word* perms = (Word*) &memory->perms[address];
    Word perm_bits = *perms;

    if (UNLIKELY((perm_bits & {mask_write_word:#x}U) != {mask_write_word:#x}U)) {{
        return 0;
    }}

    perm_bits &= {mask_clear_uninit_word:#x}U;
    *perms = perm_bits;
    *content = (Word) value;

    mark_offset_dirty(memory, address, sizeof(Word));
    return 1;
}}

static int store_memory_dword (Context* ctx, uint64_t address, uint64_t value) {{
    if (UNLIKELY(saturating_add64(address, sizeof(Dword)) > {0}ULL)) {{
        return 0;
    }}
    
    Memory* memory = ctx->memory;
    Dword* content = (Dword*) &memory->content[address];
    Dword* perms = (Dword*) &memory->perms[address];
    Dword perm_bits = *perms;

    if (UNLIKELY((perm_bits & {mask_write_dword:#x}ULL) != {mask_write_dword:#x}ULL)) {{
        return 0;
    }}

    perm_bits &= {mask_clear_uninit_dword:#x}ULL;
    *perms = perm_bits;
    *content = (Dword) value;

    mark_offset_dirty(memory, address, sizeof(Dword));
    return 1;
}}
",
            memory.size(),
        )?;

        Ok(())
    }

    fn emit_load_memory(&mut self, out_file: &mut BufWriter<File>, memory: &Memory) -> Result<(), CLifterError> {
        let mask_read_uninit_byte = perms::PERM_READ | perms::PERM_UNINIT;
        let mask_read_byte = perms::PERM_READ;
        let mask_uninit_byte = perms::PERM_UNINIT;

        let mask_read_uninit_hword = broadcast_perm::<u16>(perms::PERM_READ | perms::PERM_UNINIT);
        let mask_read_hword = broadcast_perm::<u16>(perms::PERM_READ);
        let mask_uninit_hword = broadcast_perm::<u16>(perms::PERM_UNINIT);

        let mask_read_uninit_word = broadcast_perm::<u32>(perms::PERM_READ | perms::PERM_UNINIT);
        let mask_read_word = broadcast_perm::<u32>(perms::PERM_READ);
        let mask_uninit_word = broadcast_perm::<u32>(perms::PERM_UNINIT);

        let mask_read_uninit_dword = broadcast_perm::<u64>(perms::PERM_READ | perms::PERM_UNINIT);
        let mask_read_dword = broadcast_perm::<u64>(perms::PERM_READ);
        let mask_uninit_dword = broadcast_perm::<u64>(perms::PERM_UNINIT);

        writeln!(
            out_file,
            "
static int load_memory_byte (Context* ctx, uint64_t address, uint64_t* value) {{
    if (UNLIKELY(saturating_add64(address, sizeof(Byte)) > {0}ULL)) {{
        ctx->return_buf->code = RETURN_INVALID_READ;
        return 0;
    }}
    
    Memory* memory = ctx->memory;
    Byte* content = (Byte*) &memory->content[address];
    Byte* perms = (Byte*) &memory->perms[address];

    if (UNLIKELY((*perms & {mask_read_uninit_byte:#x}U) != {mask_read_byte:#x}U)) {{
        ctx->return_buf->code = (*perms & {mask_uninit_byte:#x}U) ? RETURN_UNINIT_READ : RETURN_INVALID_READ;
        return 0;
    }}

    *value = (uint64_t) *content;
    return 1;
}}

static int load_memory_hword (Context* ctx, uint64_t address, uint64_t* value) {{
    if (UNLIKELY(saturating_add64(address, sizeof(Hword)) > {0}ULL)) {{
        ctx->return_buf->code = RETURN_INVALID_READ;
        return 0;
    }}
    
    Memory* memory = ctx->memory;
    Hword* content = (Hword*) &memory->content[address];
    Hword* perms = (Hword*) &memory->perms[address];

    if (UNLIKELY((*perms & {mask_read_uninit_hword:#x}U) != {mask_read_hword:#x}U)) {{
        ctx->return_buf->code = (*perms & {mask_uninit_hword:#x}U) ? RETURN_UNINIT_READ : RETURN_INVALID_READ;
        return 0;
    }}

    *value = (uint64_t) *content;
    return 1;
}}

static int load_memory_word (Context* ctx, uint64_t address, uint64_t* value) {{
    if (UNLIKELY(saturating_add64(address, sizeof(Word)) > {0}ULL)) {{
        ctx->return_buf->code = RETURN_INVALID_READ;
        return 0;
    }}
    
    Memory* memory = ctx->memory;
    Word* content = (Word*) &memory->content[address];
    Word* perms = (Word*) &memory->perms[address];

    if (UNLIKELY((*perms & {mask_read_uninit_word:#x}U) != {mask_read_word:#x}U)) {{
        ctx->return_buf->code = (*perms & {mask_uninit_word:#x}U) ? RETURN_UNINIT_READ : RETURN_INVALID_READ;
        return 0;
    }}

    *value = (uint64_t) *content;
    return 1;
}}

static int load_memory_dword (Context* ctx, uint64_t address, uint64_t* value) {{
    if (UNLIKELY(saturating_add64(address, sizeof(Dword)) > {0}ULL)) {{
        ctx->return_buf->code = RETURN_INVALID_READ;
        return 0;
    }}
    
    Memory* memory = ctx->memory;
    Dword* content = (Dword*) &memory->content[address];
    Dword* perms = (Dword*) &memory->perms[address];

    if (UNLIKELY((*perms & {mask_read_uninit_dword:#x}ULL) != {mask_read_dword:#x}ULL)) {{
        ctx->return_buf->code = (*perms & {mask_uninit_dword:#x}ULL) ? RETURN_UNINIT_READ : RETURN_INVALID_READ;
        return 0;
    }}

    *value = (uint64_t) *content;
    return 1;
}}
",
            memory.size(),
        )?;

        Ok(())
    }

    fn emit_entrypoint(&mut self, out_file: &mut BufWriter<File>) -> Result<(), CLifterError> {
        writeln!(
            out_file,
            "
__attribute__((visibility(\"default\")))
uint64_t run (void* memory, void* event_channel, void* registers, void* return_buf, void* static_variables) {{
    Context ctx = {{
        .memory = (Memory*) memory,
        .event_channel = (EventChannel*) event_channel,
        .return_buf = (ReturnBuffer*) return_buf,
        .static_vars = (uint64_t*) static_variables,
        .registers = (Registers*) registers,
    }};
    uint64_t ret = 0;
    uint64_t num_instructions = 0;
    
    __builtin_memcpy(&local_registers, registers, sizeof(LocalRegisters));
    BasicBlockFn next_pc_func = lookup_pc(&ctx);

    while (next_pc_func) {{
        if (UNLIKELY(num_instructions >= {}ULL)) {{
            ctx.return_buf->code = RETURN_TIMEOUT;
            break;
        }}
        
        next_pc_func = (BasicBlockFn) (next_pc_func)(&ctx, &ret, &num_instructions);
    }}
    
#if {}
    ctx.return_buf->instr_count = num_instructions;
#endif
    __builtin_memcpy(registers, &local_registers, sizeof(LocalRegisters));
    return ret;
}}

#pragma clang diagnostic pop
",
            self.timeout, self.count_instructions as usize,
        )?;

        Ok(())
    }

    fn emit_subgraph(&mut self, out_file: &mut BufWriter<File>, cfg: &CFG, subgraph: &SubGraph, varstore: &VariableStorage) -> Result<(), CLifterError> {
        /* Collect addresses belonging to SubGraph */
        let mut addrs = Vec::new();
        for id in subgraph.nodes() {
            let bb = cfg.basic_block(*id).unwrap();
            addrs.push(bb.vaddr().unwrap());
        }

        /* Emit SubGraph code */
        let addr = cfg.basic_block(subgraph.entry()).unwrap().vaddr().unwrap();
        writeln!(out_file, "static void* basic_block_{:#x} (Context* ctx, uint64_t* next_pc, uint64_t* num_instructions) {{", addr)?;

        for (i, id) in subgraph.nodes().iter().enumerate() {
            let next_bb = subgraph.nodes().get(i + 1).copied();
            self.emit_basic_block(out_file, *id, next_bb, cfg, varstore, &addrs)?;
        }

        writeln!(out_file, "}}")?;
        Ok(())
    }

    fn emit_basic_block(
        &mut self,
        out_file: &mut BufWriter<File>,
        bb: Id,
        next_bb: Option<Id>,
        cfg: &CFG,
        varstore: &VariableStorage,
        addrs: &[VAddr],
    ) -> Result<(), CLifterError> {
        let bb = cfg.basic_block(bb).unwrap();
        let var_name = |var: &Var| {
            if let Some(idx) = varstore.get_static_id(bb.vaddr().unwrap(), var.id()) {
                format!("ctx->static_vars[{}]", idx)
            } else {
                format!("bb_{}_v{}", bb.id(), var.id())
            }
        };
        fn var_type(var: &Var) -> &'static str {
            match var.vartype() {
                VarType::Number => "uint64_t",
                VarType::Float32 => "float",
                VarType::Float64 => "double",
            }
        }
        let var_type_and_name = |var: &Var| {
            if let Some(idx) = varstore.get_static_id(bb.vaddr().unwrap(), var.id()) {
                format!("ctx->static_vars[{}]", idx)
            } else {
                format!("{} bb_{}_v{}", var_type(var), bb.id(), var.id())
            }
        };
        fn op_size(size: usize) -> &'static str {
            match size {
                1 => "BYTE_SIZE",
                2 => "HWORD_SIZE",
                4 => "WORD_SIZE",
                8 => "DWORD_SIZE",
                _ => unreachable!(),
            }
        }
        fn op_size_suffix(size: usize) -> &'static str {
            match size {
                1 => "byte",
                2 => "hword",
                4 => "word",
                8 => "dword",
                _ => unreachable!(),
            }
        }

        /* Label first */
        writeln!(out_file, "bb_{:#x}:;", bb.vaddr().unwrap())?;

        /* Basic block prologue */
        if self.update_pc {
            writeln!(out_file, "local_registers.pc = {:#x}ULL;", bb.vaddr().unwrap())?;
        }

        if self.count_instructions {
            let mut num_instructions = 0;

            for op in bb.ops() {
                if matches!(op, Op::NextInstruction { .. }) {
                    num_instructions += 1;
                }
            }

            if num_instructions != 0 {
                writeln!(out_file, "*num_instructions += {}ULL;", num_instructions)?;
            }
        }

        /* Emit code */
        let mut has_return = false;
        let mut engine = engine::Engine::<()>::attach(bb, None);
        engine.execute()?;

        for (op_no, op) in bb.ops().iter().enumerate() {
            match op {
                Op::NextInstruction {
                    vaddr,
                } => {
                    writeln!(out_file, "// new instr @ {:#x}", *vaddr)?;

                    if self.update_last_instr {
                        writeln!(out_file, "local_registers.current_addr = {:#x};", *vaddr)?;
                    }
                },
                Op::LoadVirtAddr {
                    dst,
                    vaddr,
                } => {
                    if matches!(AddressSpace::decode(*vaddr), AddressSpace::Code(_)) && !addrs.contains(vaddr) {
                        writeln!(out_file, "{0} = TAG_BB_ADDRESS({1:#x}ULL, basic_block_{1:#x});", var_type_and_name(dst), *vaddr)?;
                    } else {
                        writeln!(out_file, "{} = {:#x}ULL;", var_type_and_name(dst), *vaddr)?;
                    }
                },
                Op::StoreRegister {
                    reg,
                    var,
                } => match reg {
                    Register::Gp(reg) => {
                        if self.uninit_stack && *reg == GpRegister::sp {
                            writeln!(out_file, "mark_stack_uninit(ctx->memory, local_registers.gp[{}], {});", *reg as usize, var_name(var))?;
                        }

                        writeln!(out_file, "local_registers.gp[{}] = {};", *reg as usize, var_name(var),)?;
                    },
                    Register::Fp(reg) => writeln!(out_file, "ctx->registers->fp[{}] = {};", *reg as usize, var_name(var),)?,
                    Register::Csr(_) => writeln!(out_file, "ctx->registers->fcsr = {};", var_name(var),)?,
                },
                Op::LoadImmediate {
                    dst,
                    imm,
                } => {
                    writeln!(out_file, "{} = {:#x}ULL;", var_type_and_name(dst), *imm)?;
                },
                Op::Jump {
                    dst,
                } => {
                    if let engine::Value::VAddr(addr) = engine.var(*dst) {
                        if addrs.contains(addr) {
                            writeln!(out_file, "goto bb_{:#x};", addr)?;
                        } else {
                            writeln!(out_file, "return (void*) basic_block_{:#x};", addr)?;
                        }
                    } else {
                        writeln!(out_file, "return (void*) lookup_basic_block_table(ctx, {});", var_name(dst))?;
                    }
                    has_return = true;
                },
                Op::LoadRegister {
                    var,
                    reg,
                } => match reg {
                    Register::Gp(reg) => writeln!(out_file, "{} = local_registers.gp[{}];", var_type_and_name(var), *reg as usize,)?,
                    Register::Fp(reg) => writeln!(out_file, "{} = ctx->registers->fp[{}];", var_type_and_name(var), *reg as usize,)?,
                    Register::Csr(_) => writeln!(out_file, "{} = ctx->registers->fcsr;", var_type_and_name(var),)?,
                },
                Op::Add {
                    dst,
                    src1,
                    src2,
                } => {
                    writeln!(out_file, "{} = {} + {};", var_type_and_name(dst), var_name(src1), var_name(src2),)?;
                },
                Op::Compare {
                    dst,
                    lhs,
                    rhs,
                    comp,
                } => match comp {
                    Comparison::Equal => writeln!(out_file, "{} = ({} == {});", var_type_and_name(dst), var_name(lhs), var_name(rhs))?,
                    Comparison::NotEqual => writeln!(out_file, "{} = ({} != {});", var_type_and_name(dst), var_name(lhs), var_name(rhs))?,
                    Comparison::Less(signed) => {
                        if *signed {
                            assert_eq!(dst.vartype(), VarType::Number);
                            writeln!(out_file, "{} = (CONVERT(int64_t, {}) < CONVERT(int64_t, {}));", var_type_and_name(dst), var_name(lhs), var_name(rhs))?;
                        } else {
                            writeln!(out_file, "{} = ({} < {});", var_type_and_name(dst), var_name(lhs), var_name(rhs))?;
                        }
                    },
                    Comparison::LessEqual(signed) => {
                        if *signed {
                            assert_eq!(dst.vartype(), VarType::Number);
                            writeln!(out_file, "{} = (CONVERT(int64_t, {}) <= CONVERT(int64_t, {}));", var_type_and_name(dst), var_name(lhs), var_name(rhs))?;
                        } else {
                            writeln!(out_file, "{} = ({} <= {});", var_type_and_name(dst), var_name(lhs), var_name(rhs))?;
                        }
                    },
                },
                Op::Branch {
                    dst,
                    cond,
                } => {
                    if let engine::Value::VAddr(addr) = engine.var(*dst) {
                        if addrs.contains(addr) {
                            writeln!(out_file, "if (UNLIKELY({})) goto bb_{:#x};", var_name(cond), *addr)?;
                        } else {
                            writeln!(out_file, "if (UNLIKELY({})) return (void*) basic_block_{:#x};", var_name(cond), *addr)?;
                        }
                    } else {
                        writeln!(out_file, "if (UNLIKELY({})) return (void*) lookup_basic_block_table(ctx, {});", var_name(cond), var_name(dst))?;
                    }
                },
                Op::LoadMemory {
                    dst,
                    addr,
                    size,
                } => {
                    if dst.vartype() == VarType::Number {
                        writeln!(out_file, "{} = 0;", var_type_and_name(dst))?;
                        writeln!(
                            out_file,
                            "if (UNLIKELY(!load_memory_{3}(ctx, {0}, &{2}))) return (void*) fault_invalid_read(ctx, {0}, {1});",
                            var_name(addr),
                            op_size(*size),
                            var_name(dst),
                            op_size_suffix(*size)
                        )?;
                    } else {
                        writeln!(out_file, "uint64_t bb_{}_tmp_{} = 0;", bb.id(), op_no)?;
                        writeln!(
                            out_file,
                            "if (UNLIKELY(!load_memory_{4}(ctx, {0}, &bb_{3}_tmp_{2}))) return (void*) fault_invalid_read(ctx, {0}, {1});",
                            var_name(addr),
                            op_size(*size),
                            op_no,
                            bb.id(),
                            op_size_suffix(*size)
                        )?;
                        writeln!(out_file, "{} = REINTERPRET({}, bb_{}_tmp_{});", var_type_and_name(dst), var_type(dst), bb.id(), op_no)?;
                    }
                },
                Op::SignExtend {
                    dst,
                    src,
                    size,
                } => match *size {
                    1 => writeln!(out_file, "{} = CONVERT({}, EXTEND(int8_t, int64_t, {}));", var_type_and_name(dst), var_type(dst), var_name(src))?,
                    2 => writeln!(out_file, "{} = CONVERT({}, EXTEND(int16_t, int64_t, {}));", var_type_and_name(dst), var_type(dst), var_name(src))?,
                    4 => writeln!(out_file, "{} = CONVERT({}, EXTEND(int32_t, int64_t, {}));", var_type_and_name(dst), var_type(dst), var_name(src))?,
                    _ => unreachable!(),
                },
                Op::StoreMemory {
                    addr,
                    src,
                    size,
                } => {
                    writeln!(
                        out_file,
                        "if (UNLIKELY(!store_memory_{3}(ctx, {0}, REINTERPRET(uint64_t, {2})))) return (void*) fault_invalid_write(ctx, {0}, {1});",
                        var_name(addr),
                        op_size(*size),
                        var_name(src),
                        op_size_suffix(*size)
                    )?;
                },
                Op::Xor {
                    dst,
                    src1,
                    src2,
                } => {
                    writeln!(out_file, "{} = {} ^ {};", var_type_and_name(dst), var_name(src1), var_name(src2))?;
                },
                Op::Or {
                    dst,
                    src1,
                    src2,
                } => {
                    writeln!(out_file, "{} = {} | {};", var_type_and_name(dst), var_name(src1), var_name(src2))?;
                },
                Op::And {
                    dst,
                    src1,
                    src2,
                } => {
                    writeln!(out_file, "{} = {} & {};", var_type_and_name(dst), var_name(src1), var_name(src2))?;
                },
                Op::Sub {
                    dst,
                    lhs,
                    rhs,
                } => {
                    writeln!(out_file, "{} = {} - {};", var_type_and_name(dst), var_name(lhs), var_name(rhs))?;
                },
                Op::ShiftLeft {
                    dst,
                    src,
                    amount,
                } => {
                    writeln!(out_file, "{} = {} << {};", var_type_and_name(dst), var_name(src), var_name(amount))?;
                },
                Op::ShiftRight {
                    dst,
                    src,
                    amount,
                    arithmetic,
                } => {
                    if *arithmetic {
                        writeln!(out_file, "{} = CONVERT({}, CONVERT(int64_t, {}) >> {});", var_type_and_name(dst), var_type(dst), var_name(src), var_name(amount))?;
                    } else {
                        writeln!(out_file, "{} = {} >> {};", var_type_and_name(dst), var_name(src), var_name(amount))?;
                    }
                },
                Op::Nop => {},
                Op::PushEventArgs {
                    args,
                } => {
                    writeln!(out_file, "ctx->event_channel->length = {};", args.len())?;
                    for (i, arg) in args.iter().enumerate() {
                        writeln!(out_file, "ctx->event_channel->data[{}] = REINTERPRET(uint64_t, {});", i, var_name(arg))?;
                    }
                },
                Op::FireEvent {
                    event,
                } => {
                    writeln!(out_file, "ctx->return_buf->code = RETURN_EVENT;")?;
                    writeln!(out_file, "ctx->return_buf->arg0 = {};", event.id())?;
                    for edge in bb.edges() {
                        if let Edge::Next(id) = edge {
                            let addr = cfg.basic_block(*id).unwrap().vaddr().unwrap();
                            writeln!(out_file, "*next_pc = TAG_BB_ADDRESS({0:#x}ULL, basic_block_{0:#x});", addr)?;
                            break;
                        }
                    }
                    writeln!(out_file, "return NULL;")?;
                    has_return = true;
                },
                Op::CollectEventReturns {
                    vars,
                } => {
                    writeln!(
                        out_file,
                        "if (UNLIKELY(ctx->event_channel->length != {0})) return (void*) fault_invalid_event_channel(ctx, {0}, ctx->event_channel->length);",
                        vars.len()
                    )?;
                    for (i, var) in vars.iter().enumerate() {
                        writeln!(out_file, "{} = ctx->event_channel->data[{}];", var_type_and_name(var), i)?;
                    }
                },
                Op::ZeroExtend {
                    dst,
                    src,
                    size,
                } => match *size {
                    1 => writeln!(out_file, "{} = EXTEND(uint8_t, {}, {});", var_type_and_name(dst), var_type(dst), var_name(src))?,
                    2 => writeln!(out_file, "{} = EXTEND(uint16_t, {}, {});", var_type_and_name(dst), var_type(dst), var_name(src))?,
                    4 => writeln!(out_file, "{} = EXTEND(uint32_t, {}, {});", var_type_and_name(dst), var_type(dst), var_name(src))?,
                    _ => unreachable!(),
                },
                Op::Invert {
                    dst,
                    src,
                } => {
                    writeln!(out_file, "{} = ~{};", var_type_and_name(dst), var_name(src))?;
                },
                Op::Min {
                    dst,
                    src1,
                    src2,
                    signs,
                } => match signs {
                    Signedness::Unsigned => {
                        writeln!(out_file, "{} = MIN({}, {});", var_type_and_name(dst), var_name(src1), var_name(src2))?;
                    },
                    _ => {
                        assert_eq!(dst.vartype(), VarType::Number);
                        writeln!(
                            out_file,
                            "{} = CONVERT({}, MIN(CONVERT(int64_t, {}), CONVERT(int64_t, {})));",
                            var_type_and_name(dst),
                            var_type(dst),
                            var_name(src1),
                            var_name(src2)
                        )?;
                    },
                },
                Op::Max {
                    dst,
                    src1,
                    src2,
                    signs,
                } => match signs {
                    Signedness::Unsigned => {
                        writeln!(out_file, "{} = MAX({}, {});", var_type_and_name(dst), var_name(src1), var_name(src2))?;
                    },
                    _ => {
                        assert_eq!(dst.vartype(), VarType::Number);
                        writeln!(
                            out_file,
                            "{} = CONVERT({}, MAX(CONVERT(int64_t, {}), CONVERT(int64_t, {})));",
                            var_type_and_name(dst),
                            var_type(dst),
                            var_name(src1),
                            var_name(src2)
                        )?;
                    },
                },
                Op::NaNBox {
                    dst,
                    src,
                } => {
                    writeln!(out_file, "uint64_t bb_{}_tmp_{} = {:#x}ULL | CONVERT(uint64_t, REINTERPRET(uint32_t, {}));", bb.id(), op_no, NAN_BOX, var_name(src))?;
                    writeln!(out_file, "{} = REINTERPRET(double, bb_{}_tmp_{});", var_type_and_name(dst), bb.id(), op_no)?;
                },
                Op::ReinterpretAsFloat32 {
                    dst,
                    src,
                } => {
                    writeln!(out_file, "{} = REINTERPRET(float, {});", var_type_and_name(dst), var_name(src))?;
                },
                Op::ReinterpretAsFloat64 {
                    dst,
                    src,
                } => {
                    writeln!(out_file, "{} = REINTERPRET(double, {});", var_type_and_name(dst), var_name(src))?;
                },
                Op::MultiplyAdd {
                    dst,
                    src1,
                    src2,
                    src3,
                } => {
                    writeln!(out_file, "{} = {} * {} + {};", var_type_and_name(dst), var_name(src1), var_name(src2), var_name(src3))?;
                },
                Op::NaNUnbox {
                    dst,
                    src,
                } => {
                    writeln!(out_file, "{} = REINTERPRET(float, {});", var_type_and_name(dst), var_name(src))?;
                },
                Op::Negate {
                    dst,
                    src,
                } => {
                    writeln!(out_file, "{} = -{};", var_type_and_name(dst), var_name(src))?;
                },
                Op::Multiply {
                    dst,
                    src1,
                    src2,
                    half,
                    signs,
                } => match dst.vartype() {
                    VarType::Number => {
                        writeln!(out_file, "uint128_t bb_{}_tmp_{};", bb.id(), op_no)?;
                        match signs {
                            Signedness::Unsigned => {
                                writeln!(out_file, "bb_{}_tmp_{} = CONVERT(uint128_t, {}) * CONVERT(uint128_t, {});", bb.id(), op_no, var_name(src1), var_name(src2))?;
                            },
                            Signedness::Signed => {
                                writeln!(
                                    out_file,
                                    "bb_{}_tmp_{} = CONVERT(uint128_t, EXTEND(int64_t, int128_t, {})) * CONVERT(uint128_t, EXTEND(int64_t, int128_t, {}));",
                                    bb.id(),
                                    op_no,
                                    var_name(src1),
                                    var_name(src2)
                                )?;
                            },
                            Signedness::Mixed => {
                                writeln!(
                                    out_file,
                                    "bb_{}_tmp_{} = CONVERT(uint128_t, EXTEND(int64_t, int128_t, {})) * EXTEND(uint64_t, uint128_t, {});",
                                    bb.id(),
                                    op_no,
                                    var_name(src1),
                                    var_name(src2)
                                )?;
                            },
                        }
                        match half {
                            Half::Lower => writeln!(out_file, "{} = CONVERT({}, bb_{}_tmp_{});", var_type_and_name(dst), var_type(dst), bb.id(), op_no)?,
                            Half::Upper => writeln!(out_file, "{} = CONVERT({}, bb_{}_tmp_{} >> 64);", var_type_and_name(dst), var_type(dst), bb.id(), op_no)?,
                        }
                    },
                    _ => writeln!(out_file, "{} = {} * {};", var_type_and_name(dst), var_name(src1), var_name(src2))?,
                },
                Op::Divide {
                    dst,
                    src1,
                    src2,
                    ..
                } => {
                    if dst.vartype() == VarType::Number {
                        if self.allow_div_by_zero {
                            writeln!(out_file, "{};", var_type_and_name(dst))?;
                            writeln!(out_file, "if (UNLIKELY({} == 0)) {{ {} = 0; }}", var_name(src2), var_name(dst))?;
                            writeln!(out_file, "else {{ {} = {} / {}; }}", var_name(dst), var_name(src1), var_name(src2))?;
                        } else {
                            writeln!(out_file, "if (UNLIKELY({} == 0)) return (void*) fault_div_by_zero(ctx);", var_name(src2))?;
                            writeln!(out_file, "{} = {} / {};", var_type_and_name(dst), var_name(src1), var_name(src2))?;
                        }
                    } else {
                        writeln!(out_file, "{} = {} / {};", var_type_and_name(dst), var_name(src1), var_name(src2))?;
                    }
                },
                Op::Sqrt {
                    dst,
                    src,
                } => {
                    assert_ne!(dst.vartype(), VarType::Number);
                    writeln!(out_file, "{} = __builtin_sqrt({});", var_type_and_name(dst), var_name(src))?;
                },
                Op::ReinterpretAsInteger {
                    dst,
                    src,
                } => {
                    writeln!(out_file, "{} = REINTERPRET(uint64_t, {});", var_type_and_name(dst), var_name(src))?;
                },
                Op::Classify {
                    dst,
                    src,
                } => match src.vartype() {
                    VarType::Number => unreachable!(),
                    VarType::Float32 => writeln!(out_file, "{} = classify32({});", var_type_and_name(dst), var_name(src))?,
                    VarType::Float64 => writeln!(out_file, "{} = classify64({});", var_type_and_name(dst), var_name(src))?,
                },
                Op::ConvertToInteger32 {
                    dst,
                    src,
                    sign,
                } => match sign {
                    Signedness::Unsigned => {
                        writeln!(out_file, "{} = CONVERT({}, CONVERT(uint32_t, {}));", var_type_and_name(dst), var_type(dst), var_name(src))?;
                    },
                    _ => {
                        writeln!(out_file, "{} = CONVERT({}, CONVERT(int32_t, {}));", var_type_and_name(dst), var_type(dst), var_name(src))?;
                    },
                },
                Op::ConvertToInteger64 {
                    dst,
                    src,
                    sign,
                }
                | Op::ConvertToFloat64 {
                    dst,
                    src,
                    sign,
                }
                | Op::ConvertToFloat32 {
                    dst,
                    src,
                    sign,
                } => match sign {
                    Signedness::Unsigned => {
                        writeln!(out_file, "{} = CONVERT({}, {});", var_type_and_name(dst), var_type(dst), var_name(src))?;
                    },
                    _ => {
                        writeln!(out_file, "{} = CONVERT({}, CONVERT(int64_t, {}));", var_type_and_name(dst), var_type(dst), var_name(src))?;
                    },
                },
                Op::Remainder {
                    dst,
                    src1,
                    src2,
                    signs,
                } => match signs {
                    Signedness::Unsigned => {
                        writeln!(out_file, "{} = {} % {};", var_type_and_name(dst), var_name(src1), var_name(src2))?;
                    },
                    _ => {
                        writeln!(
                            out_file,
                            "{} = CONVERT({}, CONVERT(int64_t, {}) % CONVERT(int64_t, {}));",
                            var_type_and_name(dst),
                            var_type(dst),
                            var_name(src1),
                            var_name(src2)
                        )?;
                    },
                },
                Op::ConvertNaN {
                    dst,
                    src,
                }
                | Op::Round {
                    dst,
                    src,
                    ..
                }
                | Op::Copy {
                    dst,
                    src,
                } => {
                    writeln!(out_file, "{} = {};", var_type_and_name(dst), var_name(src))?;
                },
                Op::LoadPointer {
                    ..
                } => unreachable!("Tried to compile not fully concretized code"),
            }
        }

        if !has_return {
            for edge in bb.edges() {
                if let Edge::Next(id) = edge {
                    let addr = cfg.basic_block(*id).unwrap().vaddr().unwrap();

                    if addrs.contains(&addr) {
                        if Some(*id) != next_bb {
                            writeln!(out_file, "goto bb_{:#x};", addr)?;
                        }
                    } else {
                        writeln!(out_file, "return (void*) basic_block_{:#x}(ctx, next_pc, num_instructions);", addr)?;
                    }

                    has_return = true;
                    break;
                }
            }

            if !has_return {
                writeln!(out_file, "ctx->return_buf->code = RETURN_INVALID_STATE;")?;
                writeln!(out_file, "return NULL;")?;
            }
        }

        Ok(())
    }
}
