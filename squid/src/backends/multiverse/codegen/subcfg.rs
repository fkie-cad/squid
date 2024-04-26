use std::collections::HashSet;

use crate::frontend::{
    ao::{
        Edge,
        Function,
        Op,
        CFG,
    },
    HasId,
    Id,
};

pub(crate) struct SubGraph {
    entry: Id,
    nodes: Vec<Id>,
}

impl SubGraph {
    pub(crate) fn entry(&self) -> Id {
        self.entry
    }

    pub(crate) fn nodes(&self) -> &[Id] {
        &self.nodes
    }
}

struct GraphWalker {
    nodes: Vec<Id>,
    cursor: usize,
}

impl GraphWalker {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            cursor: 0,
        }
    }

    fn push(&mut self, node: Id) {
        if !self.nodes.contains(&node) {
            self.nodes.push(node);
        }
    }

    fn next(&mut self) -> Option<Id> {
        if self.cursor < self.nodes.len() {
            let elem = self.nodes[self.cursor];
            self.cursor += 1;
            Some(elem)
        } else {
            None
        }
    }
}

struct SubCFGBuilder<'a> {
    cfg: &'a CFG,
    entry_points: HashSet<Id>,
    subgraphs: Vec<Vec<Id>>,
}

impl<'a> SubCFGBuilder<'a> {
    fn new(cfg: &'a CFG) -> Self {
        let mut entry_points = HashSet::new();
        entry_points.insert(cfg.entry());

        Self {
            cfg,
            entry_points,
            subgraphs: Vec::new(),
        }
    }

    fn find_entry_points(&mut self) {
        for bb in self.cfg.iter_basic_blocks() {
            match bb.ops().last() {
                Some(Op::FireEvent {
                    ..
                }) => {
                    if !bb.edges().is_empty() {
                        assert_eq!(bb.edges().len(), 1);
                        let Edge::Next(target) = bb.edges()[0] else { unreachable!() };
                        self.entry_points.insert(target);
                    }
                },
                Some(Op::Jump {
                    ..
                }) => {
                    for edge in bb.edges() {
                        if let Edge::Next(target) = edge {
                            self.entry_points.insert(*target);
                        }
                    }
                },
                _ => {},
            }
        }
    }

    fn calculate_subgraphs(&mut self) {
        self.subgraphs.clear();
        let mut walker = GraphWalker::new();

        for entry in &self.entry_points {
            let mut subgraph = Vec::new();
            walker.push(*entry);

            while let Some(next) = walker.next() {
                subgraph.push(next);

                let bb = self.cfg.basic_block(next).unwrap();
                for edge in bb.edges() {
                    let target = edge.target();

                    if !self.entry_points.contains(&target) {
                        walker.push(target);
                    }
                }
            }

            self.subgraphs.push(subgraph);
        }
    }

    fn check_connectedness(&mut self) -> bool {
        let prev_len = self.entry_points.len();

        for subgraph in &self.subgraphs {
            for id in subgraph {
                let bb = self.cfg.basic_block(*id).unwrap();

                for edge in bb.edges() {
                    let target = edge.target();

                    if !subgraph.contains(&target) {
                        self.entry_points.insert(target);
                    }
                }
            }
        }

        self.entry_points.len() > prev_len
    }

    fn verify(&self) {
        let mut num_bb = 0;

        for subgraph in &self.subgraphs {
            assert!(!subgraph.is_empty());
            num_bb += subgraph.len();
        }

        assert_eq!(self.cfg.num_basic_blocks(), num_bb);
    }

    fn into_subgraphs(self) -> Vec<SubGraph> {
        let mut ret = Vec::new();

        for subgraph in self.subgraphs {
            let entry = subgraph[0];
            ret.push(SubGraph {
                entry,
                nodes: subgraph,
            });
        }

        ret
    }
}

pub(crate) fn split_into_subgraphs(func: &Function) -> Vec<SubGraph> {
    if func.perfect() {
        let mut builder = SubCFGBuilder::new(func.cfg());
        builder.find_entry_points();
        builder.calculate_subgraphs();

        while builder.check_connectedness() {
            builder.calculate_subgraphs();
        }

        builder.verify();
        builder.into_subgraphs()
    } else {
        let mut ret = Vec::new();

        for bb in func.cfg().iter_basic_blocks() {
            ret.push(SubGraph {
                entry: bb.id(),
                nodes: vec![bb.id()],
            });
        }

        ret
    }
}
