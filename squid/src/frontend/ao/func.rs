use crate::frontend::ao::CFG;

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

    pub fn cfg(&self) -> &CFG {
        &self.cfg
    }

    pub fn cfg_mut(&mut self) -> &mut CFG {
        &mut self.cfg
    }

    pub fn perfect(&self) -> bool {
        self.perfect
    }
}
