use crate::frontend::{
    ao::{
        Edge,
        Function,
    },
    HasId,
};

pub(crate) struct EliminateEmptyBasicBlocksPass {}

impl EliminateEmptyBasicBlocksPass {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn run(&mut self, func: &mut Function) -> Result<(), String> {
        for bb in func.cfg_mut().iter_basic_blocks_mut() {
            if bb.ops().is_empty() {
                let mut next = None;

                for edge in bb.edges() {
                    match edge {
                        Edge::Next(id) => {
                            assert!(next.is_none());
                            next = Some(*id);
                        },
                        Edge::Jump(_) => return Err("Empty basic block with a jump edge".to_string()),
                    }
                }

                if let Some(next) = next {
                    assert_ne!(bb.id(), next);

                    bb.set_cursor(0);
                    bb.nop();
                } else {
                    todo!("???");
                }
            }
        }

        Ok(())
    }
}
