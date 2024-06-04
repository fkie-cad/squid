use std::collections::HashMap;

use crate::{
    frontend::{
        ao::{
            engine::{
                Engine,
                Value,
            },
            BasicBlock,
            Edge,
            Function,
            Op,
            Register,
            Var,
        },
        HasId,
        Id,
        VAddr,
    },
    riscv::register::GpRegister,
};

fn filter_virtaddr(value: &Value) -> Value {
    match value {
        Value::VAddr(addr) => Value::VAddr(*addr),
        _ => Value::Unknown,
    }
}

fn get_register_state(bb: &BasicBlock) -> Vec<Value> {
    let mut result = vec![];
    let mut engine = Engine::<()>::attach(bb, None);

    engine.execute().unwrap();

    for i in 0..32 {
        let value = engine.get_register(&Register::Gp(GpRegister::from_usize(i)));
        result.push(filter_virtaddr(value));
    }

    result
}

#[derive(Copy, Clone, PartialEq)]
enum Usage {
    Normal,
    Temp,
    Perm,
}

struct DataflowInfo {
    forward_matrix: Vec<Vec<bool>>,
    backwards_matrix: Vec<Vec<bool>>,
    entrypoints: Vec<usize>,
    copy_targets: Vec<Option<usize>>,
    vars: Vec<Value>,
    uses: Vec<Usage>,
}

impl DataflowInfo {
    fn new(bb: &BasicBlock) -> Self {
        let mut forward_matrix: Vec<Vec<bool>> = vec![vec![false; bb.num_variables()]; bb.num_variables()];
        let mut backwards_matrix: Vec<Vec<bool>> = vec![vec![false; bb.num_variables()]; bb.num_variables()];
        let mut engine = Engine::<()>::attach(bb, None);
        let mut entrypoints = Vec::new();
        let mut copy_targets = vec![None; bb.num_variables()];
        let uses = vec![Usage::Normal; bb.num_variables()];

        engine.execute().unwrap();

        for op in bb.ops() {
            if let Op::Copy {
                dst,
                src,
            } = op
            {
                copy_targets[dst.id()] = Some(src.id());
            } else if let Op::LoadVirtAddr {
                dst,
                ..
            } = op
            {
                entrypoints.push(dst.id());
            }

            for out_var in op.output_variables() {
                for in_var in op.input_variables() {
                    forward_matrix[in_var.id()][out_var.id()] = true;
                    backwards_matrix[out_var.id()][in_var.id()] = true;
                }
            }
        }

        Self {
            forward_matrix,
            backwards_matrix,
            entrypoints,
            copy_targets,
            vars: engine.vars().to_owned(),
            uses,
        }
    }

    fn graph_get_sinks(&self, var: usize) -> Vec<usize> {
        assert!(matches!(&self.vars[var], Value::VAddr(_)));

        let mut ret = Vec::new();

        for (i, trans) in self.forward_matrix[var].iter().enumerate() {
            if *trans {
                assert!(i > var);

                if let Value::VAddr(_) = &self.vars[i] {
                    ret.extend_from_slice(&self.graph_get_sinks(i));
                } else {
                    ret.push(var);
                }
            }
        }

        if ret.is_empty() {
            ret.push(var);
        }

        ret
    }

    fn mark_sources_as_temporary(&mut self, sink: usize) {
        for i in 0..self.backwards_matrix.len() {
            if self.backwards_matrix[sink][i] {
                assert_ne!(i, sink);

                if self.uses[i] == Usage::Normal {
                    self.uses[i] = Usage::Temp;
                }

                self.mark_sources_as_temporary(i);
            }
        }
    }

    fn follow_copies(&self, mut var: usize) -> usize {
        loop {
            if let Some(src) = self.copy_targets[var] {
                var = src;
            } else {
                return var;
            }
        }
    }

    fn analyze_usage(&mut self, debug: bool) {
        for i in 0..self.entrypoints.len() {
            let source = self.entrypoints[i];

            for sink in self.graph_get_sinks(source) {
                let sink = self.follow_copies(sink);

                if debug {
                    println!("source={} sink={}", source, sink);
                }

                if source != sink {
                    self.mark_sources_as_temporary(sink);
                }

                self.uses[sink] = Usage::Perm;
            }
        }
    }

    fn usage(&self, var: &Var) -> Usage {
        self.uses[var.id()]
    }

    fn address(&self, var: &Var) -> VAddr {
        let Value::VAddr(addr) = &self.vars[var.id()] else { unreachable!() };
        *addr
    }
}

fn count_ingoing_edges(func: &Function) -> HashMap<Id, usize> {
    let mut result = HashMap::new();

    for bb in func.cfg().iter_basic_blocks() {
        for edge in bb.edges() {
            let target = edge.target();
            *result.entry(target).or_insert(0) += 1;
        }
    }

    result
}

pub(crate) struct AddressPropagationPass {
    imports: Vec<(Id, Id)>,
    order: Vec<Id>,
}

impl AddressPropagationPass {
    pub(crate) fn new() -> Self {
        Self {
            imports: Vec::new(),
            order: Vec::new(),
        }
    }

    fn build_imports(&mut self, func: &Function) {
        let ingoing_count = count_ingoing_edges(func);

        for bb in func.cfg().iter_basic_blocks() {
            let edges = bb.edges();

            if edges.len() != 1 {
                continue;
            }

            if let Edge::Next(target) = &edges[0] {
                if *target == func.cfg().entry() {
                    continue;
                }

                let count = *ingoing_count.get(target).unwrap_or(&0);

                if count == 1 {
                    self.imports.push((bb.id(), *target));
                }
            }
        }
    }

    fn import(&self, bb: Id) -> Option<Id> {
        for (src, dst) in &self.imports {
            if *dst == bb {
                return Some(*src);
            }
        }

        None
    }

    fn add_to_order(&mut self, target: Id) {
        if self.order.contains(&target) {
            return;
        }

        if let Some(bb) = self.import(target) {
            self.add_to_order(bb);
        }

        self.order.push(target);
    }

    fn build_propagation_order(&mut self, func: &Function) {
        self.add_to_order(func.cfg().entry());

        for bb in func.cfg().iter_basic_blocks() {
            self.add_to_order(bb.id());
        }

        assert_eq!(self.order.len(), func.cfg().num_basic_blocks());
    }

    fn preprocess(&mut self, func: &mut Function) {
        let mut states = HashMap::new();

        for id in &self.order {
            if let Some(ancestor) = self.import(*id) {
                let bb = func.cfg().basic_block(ancestor).unwrap();
                let state = states.entry(ancestor).or_insert_with(|| get_register_state(bb));

                if !bb.has_continuous_flow() {
                    /* Reset registers based on ABI */
                    state[GpRegister::ra as usize] = Value::Unknown;
                    state[GpRegister::t0 as usize] = Value::Unknown;
                    state[GpRegister::t1 as usize] = Value::Unknown;
                    state[GpRegister::t2 as usize] = Value::Unknown;
                    state[GpRegister::t3 as usize] = Value::Unknown;
                    state[GpRegister::t4 as usize] = Value::Unknown;
                    state[GpRegister::t5 as usize] = Value::Unknown;
                    state[GpRegister::t6 as usize] = Value::Unknown;
                    state[GpRegister::a0 as usize] = Value::Unknown;
                    state[GpRegister::a1 as usize] = Value::Unknown;
                    state[GpRegister::a2 as usize] = Value::Unknown;
                    state[GpRegister::a3 as usize] = Value::Unknown;
                    state[GpRegister::a4 as usize] = Value::Unknown;
                    state[GpRegister::a5 as usize] = Value::Unknown;
                    state[GpRegister::a6 as usize] = Value::Unknown;
                    state[GpRegister::a7 as usize] = Value::Unknown;
                }

                let bb = func.cfg_mut().basic_block_mut(*id).unwrap();
                bb.set_cursor(0);

                while let Some(op) = bb.cursor_op() {
                    match op {
                        Op::LoadRegister {
                            var,
                            reg: Register::Gp(reg),
                        } => {
                            if let Value::VAddr(addr) = &state[*reg as usize] {
                                bb.replace_op(Op::LoadVirtAddr {
                                    dst: *var,
                                    vaddr: *addr,
                                });
                            }
                        },
                        Op::StoreRegister {
                            reg: Register::Gp(reg),
                            var,
                        } => {
                            //TODO: extremely ineffecient
                            let mut engine = Engine::<()>::attach(bb, None);
                            engine.execute().unwrap();

                            state[*reg as usize] = filter_virtaddr(engine.var(*var));
                        },
                        _ => {},
                    }

                    if !bb.move_cursor_forward() {
                        break;
                    }
                }

                let state = state.clone();
                states.insert(*id, state);
            }
        }
    }

    fn propagate(&mut self, func: &mut Function) {
        for bb in func.cfg_mut().iter_basic_blocks_mut() {
            let debug = false;

            /*if bb.vaddr() == Some(0x639f0) {
                println!("{:#?}", bb.ops());
                debug = true;
            }*/

            let mut dataflow = DataflowInfo::new(bb);
            dataflow.analyze_usage(debug);

            bb.set_cursor(0);

            while let Some(op) = bb.cursor_op() {
                let out_vars = op.output_variables();

                if !out_vars.is_empty() {
                    assert_eq!(out_vars.len(), 1);

                    match dataflow.usage(&out_vars[0]) {
                        Usage::Temp => {
                            bb.delete_op();
                            continue;
                        },
                        Usage::Perm => {
                            bb.replace_op(Op::LoadVirtAddr {
                                dst: out_vars[0],
                                vaddr: dataflow.address(&out_vars[0]),
                            });
                        },
                        _ => {},
                    }
                } else {
                    let in_vars = op.input_variables();
                    let mut score = 0;

                    for in_var in &in_vars {
                        score += (dataflow.usage(in_var) == Usage::Temp) as usize;
                    }

                    if !in_vars.is_empty() && score == in_vars.len() {
                        bb.delete_op();
                        continue;
                    } else {
                        assert_eq!(score, 0);
                    }
                }

                if !bb.move_cursor_forward() {
                    break;
                }
            }
        }
    }

    pub(crate) fn run(&mut self, func: &mut Function) -> Result<(), String> {
        self.build_imports(func);
        self.build_propagation_order(func);
        self.preprocess(func);
        self.propagate(func);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event::EventPool,
        frontend::ao::{
            BasicBlock,
            CFG,
        },
        riscv::register::GpRegister,
    };

    #[test]
    #[ignore]
    fn test_address_propagation() {
        let mut cfg = CFG::new();
        let mut bb = BasicBlock::new();

        let addr = bb.load_virt_addr(1288);
        bb.store_gp_register(GpRegister::a0, addr).unwrap();
        let cpy = bb.copy(addr);
        //let arg = bb.load_immediate(192);
        let arg = bb.load_gp_register(GpRegister::t0);
        let result = bb.add(cpy, arg).unwrap();
        //bb.store_gp_register(10, result).unwrap();
        bb.jump(result).unwrap();

        cfg.add_basic_block(bb);

        let mut func = Function::new(cfg, false);

        println!("{:#?}", func.cfg());
        AddressPropagationPass::new().run(&mut func).unwrap();
        println!("{:#?}", func.cfg());
    }

    #[test]
    #[ignore]
    fn test_address_propagation_disconnected() {
        let mut cfg = CFG::new();
        let mut bb = BasicBlock::new();

        let addr = bb.load_virt_addr(1288);
        let byte = bb.load_byte(addr).unwrap();
        bb.jump(byte).unwrap();

        cfg.add_basic_block(bb);

        let mut func = Function::new(cfg, false);

        println!("{:#?}", func.cfg());
        AddressPropagationPass::new().run(&mut func).unwrap();
        println!("{:#?}", func.cfg());
    }

    #[test]
    #[ignore]
    fn test_dtls_bug() {
        /*
        5827c:	0007f417          	auipc	s0,0x7f
        58280:	2ec40413          	addi	s0,s0,748
        58284:	51843503          	ld	a0,1304(s0)
        58288:	fffb3097          	auipc	ra,0xfffb3
        5828c:	158080e7          	jalr	ra,344(ra)

        58290:	50043c23          	sd	zero,1304(s0)
         */
        let mut event_pool = EventPool::new();
        let halt = event_pool.add_event("HALT");
        let mut cfg = CFG::new();

        let mut bb1 = BasicBlock::new();
        // auipc	s0,0x7f
        let addr = bb1.load_virt_addr(0x7f);
        bb1.store_gp_register(GpRegister::s0, addr).unwrap();
        // addi	s0,s0,748
        let imm = bb1.load_immediate(748);
        let s0 = bb1.copy(addr); // bb1.load_gp_register(GpRegister::s0);
        let result = bb1.add(imm, s0).unwrap();
        bb1.store_gp_register(GpRegister::s0, result).unwrap();
        // ld	a0,1304(s0)
        let s0 = bb1.copy(result); // bb1.load_gp_register(GpRegister::s0);
        let imm = bb1.load_immediate(1304);
        let addr = bb1.add(s0, imm).unwrap();
        let value = bb1.load_dword(addr).unwrap();
        bb1.store_gp_register(GpRegister::a0, value).unwrap();
        // auipc	ra,0xfffb3
        let addr = bb1.load_virt_addr(0xfffb3);
        bb1.store_gp_register(GpRegister::ra, addr).unwrap();
        // jalr	ra,344(ra)
        let ra = bb1.copy(addr); //bb1.load_gp_register(GpRegister::ra);
        let imm = bb1.load_immediate(344);
        let addr = bb1.add(ra, imm).unwrap();
        let ret = bb1.load_virt_addr(0x58290);
        bb1.store_gp_register(GpRegister::ra, ret).unwrap();
        bb1.jump(addr).unwrap();

        let mut bb2 = BasicBlock::new();
        // sd	zero,1304(s0)
        let s0 = bb2.load_gp_register(GpRegister::s0);
        let imm = bb2.load_immediate(1304);
        let addr = bb2.add(s0, imm).unwrap();
        let value = bb2.load_immediate(0);
        bb2.store_dword(addr, value).unwrap();
        let imm = bb2.load_immediate(1);
        let s0 = bb2.add(s0, imm).unwrap();
        bb2.store_gp_register(GpRegister::s0, s0).unwrap();

        let mut bb3 = BasicBlock::new();
        // sd	zero,1304(s0)
        let s0 = bb3.load_gp_register(GpRegister::s0);
        let imm = bb3.load_immediate(1304);
        let addr = bb3.add(s0, imm).unwrap();
        let value = bb3.load_immediate(0);
        bb3.store_dword(addr, value).unwrap();
        // halt the program
        bb3.fire_event(halt);

        let bb3_id = cfg.add_basic_block(bb3);
        bb2.add_edge(Edge::Next(bb3_id));

        let bb2_id = cfg.add_basic_block(bb2);
        bb1.add_edge(Edge::Next(bb2_id));

        let bb1_id = cfg.add_basic_block(bb1);
        cfg.set_entry(bb1_id);

        let perfect = cfg.verify().unwrap();
        let mut func = Function::new(cfg, perfect);

        AddressPropagationPass::new().run(&mut func).unwrap();
    }
}
