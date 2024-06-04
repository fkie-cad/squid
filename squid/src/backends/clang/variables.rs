use std::collections::HashMap;

use crate::frontend::{
    ao::{
        Edge,
        Function,
        CFG,
    },
    ChunkContent,
    HasId,
    Id,
    ProcessImage,
    VAddr,
};

fn find_definition(preds: &[(Id, Id)], defs: &HashMap<Id, Vec<bool>>, var: usize, mut curr: Id, cfg: &CFG) -> VAddr {
    loop {
        let mut found = false;

        for (to, from) in preds {
            if *to == curr {
                curr = *from;
                found = true;
                break;
            }
        }

        if !found {
            unreachable!("Variable import has no matching export");
        }

        let flags = defs.get(&curr).unwrap();

        if flags[var] {
            return cfg.basic_block(curr).unwrap().vaddr().unwrap();
        }
    }
}

pub(crate) struct VariableStorage {
    ids: HashMap<(VAddr, usize), usize>,
    counter: usize,
    num_variables: usize,
}

impl VariableStorage {
    pub(crate) fn new(image: &ProcessImage) -> Self {
        let mut storage = Self {
            ids: HashMap::default(),
            counter: 0,
            num_variables: 0,
        };

        for elf in image.iter_elfs() {
            for section in elf.iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if let ChunkContent::Code(func) = chunk.content() {
                            storage.check_function(func);
                        }
                    }
                }
            }
        }

        storage
    }

    pub(crate) fn num_variables(&self) -> usize {
        self.num_variables
    }

    pub(crate) fn get_static_id(&self, bb: VAddr, var: usize) -> Option<usize> {
        self.ids.get(&(bb, var)).copied()
    }

    fn new_static_id(&mut self, def_bb: VAddr, var: usize) -> usize {
        if let Some(id) = self.get_static_id(def_bb, var) {
            return id;
        }

        let ret = self.counter;
        self.counter += 1;
        ret
    }

    fn check_function(&mut self, func: &Function) {
        self.counter = 0;

        /* First calculate predecessors */
        let mut preds = Vec::new();

        for bb in func.cfg().iter_basic_blocks() {
            for edge in bb.edges() {
                if let Edge::Next(target) = edge {
                    assert_ne!(*target, func.cfg().entry());
                    preds.push((*target, bb.id()));
                }
            }
        }

        /* Then find variable definitions */
        let mut defs = HashMap::new();

        for bb in func.cfg().iter_basic_blocks() {
            let mut flags = vec![false; bb.num_variables()];

            for op in bb.ops() {
                for out_var in op.output_variables() {
                    flags[out_var.id()] = true;
                }
            }

            defs.insert(bb.id(), flags);
        }

        /* Finally, check for variable imports */
        for bb in func.cfg().iter_basic_blocks() {
            let flags = defs.get(&bb.id()).unwrap();

            for op in bb.ops() {
                for in_var in op.input_variables() {
                    if !flags[in_var.id()] {
                        let def_bb = find_definition(&preds, &defs, in_var.id(), bb.id(), func.cfg());
                        let static_id = self.new_static_id(def_bb, in_var.id());
                        self.ids.insert((def_bb, in_var.id()), static_id);
                        self.ids.insert((bb.vaddr().unwrap(), in_var.id()), static_id);
                    }
                }
            }
        }

        self.num_variables = std::cmp::max(self.counter, self.num_variables);
    }
}
