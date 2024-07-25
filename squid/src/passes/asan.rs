use crate::{
    frontend::{Symbol, Chunk, Perms, ProcessImage,
        ChunkContent,
        ao::{Function, BasicBlock, Edge, AoError},
    },
    event::{EventPool, EventId},
    riscv::register::GpRegister,
    passes::Pass,
    logger::Logger,
};
use std::collections::HashSet;

fn build_redzone(size: usize) -> Symbol {
    let mut redzone = Symbol::builder().private_name("(redzone)").size(size).vaddr(0).build().unwrap();
    let chunk = Chunk::builder().uninitialized_data(size, Perms::default()).vaddr(0).build().unwrap();
    redzone.insert_chunk(chunk);
    redzone
}

fn replace_function(func: &mut Function, event_pool: &mut EventPool, event_name: &str) -> Result<EventId, AoError> {
    let event_id = event_pool.add_event(event_name);

    func.cfg_mut().clear();

    let mut bb1 = BasicBlock::new();
    bb1.fire_event(event_id);

    let mut bb2 = BasicBlock::new();
    let ra = bb2.load_gp_register(GpRegister::ra);
    bb2.jump(ra)?;

    let bb2_id = func.cfg_mut().add_basic_block(bb2);
    bb1.add_edge(Edge::Next(bb2_id));
    let bb1_id = func.cfg_mut().add_basic_block(bb1);
    func.cfg_mut().set_entry(bb1_id);

    Ok(event_id)
}

/// The `AsanPass` implements instrumentation similar to LLVM's AddressSanitizer.
/// 
/// It surrounds global variables with redzones and hooks the heap functions
/// - malloc
/// - free
/// - realloc
/// - calloc
/// 
/// Whenever one of the hooked functions is called, a corresponding event is thrown (`AsanPass::EVENT_NAME_*`) that
/// must be handled by the user. The user is responsible for extracting the arguments for
/// the specific function call, realize its implementation and set the return value before
/// continuing with the execution.
/// 
/// Note that it only hooks heap function that are inside libc.so.6. If the heap functions are defined
/// in some other object, you have to manually hook them.
pub struct AsanPass {
    num_redzones: usize,
    hooked_functions: HashSet<&'static str>,
    malloc: Option<EventId>,
    free: Option<EventId>,
    realloc: Option<EventId>,
    calloc: Option<EventId>,
}

impl AsanPass {
    /// This event gets thrown on a call to `malloc()`
    pub const EVENT_NAME_MALLOC: &'static str = "asan::malloc";
    /// This event gets thrown on a call to `free()`
    pub const EVENT_NAME_FREE: &'static str = "asan::free";
    /// This event gets thrown on a call to `realloc()`
    pub const EVENT_NAME_REALLOC: &'static str = "asan::realloc";
    /// This event gets thrown on a call to `calloc()`
    pub const EVENT_NAME_CALLOC: &'static str = "asan::calloc";
    
    /// Create a new AsanPass
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            num_redzones: 0,
            hooked_functions: HashSet::new(),
            malloc: None,
            free: None,
            realloc: None,
            calloc: None,
        }
    }

    fn insert_redzones(&mut self, image: &mut ProcessImage) {
        let mut last_size = None;
        let elf = image.iter_elfs_mut().next().unwrap();

        for section in elf.iter_sections_mut() {
            if !section.perms().is_writable() {
                continue;
            }
            section.set_cursor(0);

            while let Some(symbol) = section.cursor_symbol() {
                self.num_redzones += 1;

                /* Calculate redzone sizes */
                let left_redzone_size = if let Some(last_size) = last_size { symbol.size().saturating_sub(last_size) } else { symbol.size() };
                let right_redzone_size = symbol.size();

                /* Left redzone */
                if left_redzone_size > 0 {
                    let redzone = build_redzone(left_redzone_size);
                    section.insert_symbol(redzone);
                    assert!(section.move_cursor_forward());
                }

                /* Right redzone */
                if !section.move_cursor_forward() {
                    section.move_cursor_beyond_end();
                }

                let redzone = build_redzone(right_redzone_size);
                section.insert_symbol(redzone);

                /* Adjust section itself */
                let new_size = section.size() + left_redzone_size + right_redzone_size;
                section.set_size(new_size);

                last_size = Some(right_redzone_size);

                if !section.move_cursor_forward() {
                    break;
                }
            }
        }
    }

    fn hook_heap_functions(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool) -> Result<(), AoError> {
        for elf in image.iter_elfs_mut() {
            if !elf.path().ends_with("libc.so.6") {
                continue;
            }

            for section in elf.iter_sections_mut() {
                for symbol in section.iter_symbols_mut() {
                    if symbol.name("__libc_malloc_impl").is_some() || symbol.name("__libc_malloc").is_some() {
                        let chunk = symbol.iter_chunks_mut().next().unwrap();
                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };
                        let id = replace_function(func, event_pool, Self::EVENT_NAME_MALLOC)?;
                        self.malloc = Some(id);
                        self.hooked_functions.insert("malloc");
                    } else if symbol.name("__libc_free").is_some() {
                        let chunk = symbol.iter_chunks_mut().next().unwrap();
                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };
                        let id = replace_function(func, event_pool, Self::EVENT_NAME_FREE)?;
                        self.free = Some(id);
                        self.hooked_functions.insert("free");
                    } else if symbol.name("__libc_realloc").is_some() {
                        let chunk = symbol.iter_chunks_mut().next().unwrap();
                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };
                        let id = replace_function(func, event_pool, Self::EVENT_NAME_REALLOC)?;
                        self.realloc = Some(id);
                        self.hooked_functions.insert("realloc");
                    } else if symbol.name("__libc_calloc").is_some() || symbol.name("calloc").is_some() {
                        let chunk = symbol.iter_chunks_mut().next().unwrap();
                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };
                        let id = replace_function(func, event_pool, Self::EVENT_NAME_CALLOC)?;
                        self.calloc = Some(id);
                        self.hooked_functions.insert("calloc");
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Return the event id for `malloc()`, if it was hooked
    pub fn malloc_event(&self) -> Option<EventId> {
        self.malloc
    }
    
    /// Return the event id for `free()`, if it was hooked
    pub fn free_event(&self) -> Option<EventId> {
        self.free
    }
    
    /// Return the event id for `realloc()`, if it was hooked
    pub fn realloc_event(&self) -> Option<EventId> {
        self.realloc
    }
    
    /// Return the event id for `calloc()`, if it was hooked
    pub fn calloc_event(&self) -> Option<EventId> {
        self.calloc
    }
}

impl Pass for AsanPass {
    type Error = AoError;

    fn name(&self) -> String {
        "AsanPass".to_string()
    }

    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), Self::Error> {
        self.insert_redzones(image);
        self.hook_heap_functions(image, event_pool)?;
        logger.info(format!("Surrounded {} symbols with redzones and hooked functions: {}", self.num_redzones, self.hooked_functions.iter().copied().collect::<Vec<_>>().join(", ")));
        Ok(())
    }
}
