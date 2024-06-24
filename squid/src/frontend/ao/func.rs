use crate::frontend::ao::CFG;

/// A Function corresponds to a function in an ELF file except that the
/// CFG has been reconstructed and the code has been lifted into the ΑΩ IR.
#[derive(Hash)]
pub struct Function {
    cfg: CFG,
    perfect: bool,
}

impl Function {
    pub(crate) fn new(cfg: CFG, perfect: bool) -> Self {
        Self {
            cfg,
            perfect,
        }
    }

    /// Get the CFG of this function
    pub fn cfg(&self) -> &CFG {
        &self.cfg
    }

    /// Get the CFG of this function
    pub fn cfg_mut(&mut self) -> &mut CFG {
        &mut self.cfg
    }

    /// The CFG of this function is considered "perfect" if the graph is not disconnected
    pub fn perfect(&self) -> bool {
        self.perfect
    }
}
