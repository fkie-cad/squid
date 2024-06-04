use crate::frontend::ao::Function;

pub(crate) struct DeadCodeEliminationPass {}

impl DeadCodeEliminationPass {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn run(&mut self, func: &mut Function) -> Result<(), String> {
        for bb in func.cfg_mut().iter_basic_blocks_mut() {
            let mut used = vec![0; bb.num_variables()];

            for op in bb.ops() {
                for var in op.input_variables() {
                    used[var.id()] += 1;
                }
            }

            bb.move_cursor_beyond_end();
            bb.move_cursor_backwards();

            while let Some(op) = bb.cursor_op() {
                let mut output_used = false;
                let mut has_output = false;

                for var in op.output_variables() {
                    output_used |= used[var.id()] > 0;
                    has_output = true;
                }

                if has_output && !output_used {
                    let op = bb.delete_op();

                    for var in op.input_variables() {
                        used[var.id()] -= 1;
                    }
                }

                if !bb.move_cursor_backwards() {
                    break;
                }
            }
        }

        Ok(())
    }
}
