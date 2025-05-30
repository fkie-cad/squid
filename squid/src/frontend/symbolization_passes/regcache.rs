use crate::frontend::ao::{
    Function,
    Op,
    Register,
    Var,
};

const REGISTER_COUNT: usize = 32 + 32 + 1;
fn register_index(reg: &Register) -> usize {
    match reg {
        Register::Gp(reg) => *reg as usize,
        Register::Fp(reg) => 32 + *reg as usize,
        Register::Csr(_) => 64,
    }
}

pub(crate) struct RegisterCachingPass {
    registers: [Option<Var>; REGISTER_COUNT],
}

impl RegisterCachingPass {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        Self {
            registers: [None; REGISTER_COUNT],
        }
    }

    pub(crate) fn run(&mut self, func: &mut Function) -> Result<(), String> {
        for bb in func.cfg_mut().iter_basic_blocks_mut() {
            for reg in &mut self.registers {
                *reg = None;
            }

            bb.set_cursor(0);

            while let Some(op) = bb.cursor_op() {
                match op {
                    Op::StoreRegister {
                        reg,
                        var,
                    } => {
                        self.registers[register_index(reg)] = Some(*var);
                    },
                    Op::LoadRegister {
                        var,
                        reg,
                    } => {
                        if let Some(orig_var) = &self.registers[register_index(reg)] {
                            bb.replace_op(Op::Copy {
                                dst: *var,
                                src: *orig_var,
                            });
                        }
                    },
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
