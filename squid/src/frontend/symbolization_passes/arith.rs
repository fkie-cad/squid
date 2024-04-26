use crate::frontend::ao::{
    engine::{
        Engine,
        Value,
    },
    Function,
    Op,
};

pub(crate) struct EliminateArithmeticPass {}

impl EliminateArithmeticPass {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn run(&mut self, func: &mut Function) -> Result<(), String> {
        for bb in func.cfg_mut().iter_basic_blocks_mut() {
            let vars = {
                let mut engine = Engine::<()>::attach(bb, None);

                if let Err(err) = engine.execute() {
                    return Err(format!("EngineError: {}", err));
                }

                engine.vars().to_owned()
            };

            bb.set_cursor(0);

            while let Some(op) = bb.cursor_op() {
                #[allow(clippy::single_match)]
                match op {
                    Op::Add {
                        dst,
                        src1,
                        src2,
                    } => {
                        if let Value::Integer(0) = &vars[src1.id()] {
                            bb.replace_op(Op::Copy {
                                dst: *dst,
                                src: *src2,
                            });
                        } else if let Value::Integer(0) = &vars[src2.id()] {
                            bb.replace_op(Op::Copy {
                                dst: *dst,
                                src: *src1,
                            });
                        }
                    },
                    //TODO: maybe support more arithmetic operators
                    _ => {},
                }

                if !bb.move_cursor_forward() {
                    break;
                }
            }
        }

        Ok(())
    }
}
