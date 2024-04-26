use crate::frontend::ao::{
    Function,
    Op,
};

pub(crate) struct MetadataPass {}

impl MetadataPass {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn run(&self, func: &mut Function) -> Result<(), String> {
        for bb in func.cfg_mut().iter_basic_blocks_mut() {
            let mut count = 0;
            let mut prev_cursor = None;

            bb.set_cursor(0);

            while let Some(op) = bb.cursor_op() {
                if let Op::NextInstruction {
                    ..
                } = op
                {
                    if count == 0 {
                        if let Some(prev_cursor) = prev_cursor {
                            let current_cursor = bb.cursor();
                            bb.set_cursor(prev_cursor);
                            bb.delete_op();
                            bb.set_cursor(current_cursor - 1);
                        }
                    }

                    count = 0;
                    prev_cursor = Some(bb.cursor());
                } else {
                    count += 1;
                }

                if !bb.move_cursor_forward() {
                    break;
                }
            }

            if count == 0 && prev_cursor.is_some() {
                bb.delete_op();
            }
        }

        Ok(())
    }
}
