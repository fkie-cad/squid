use std::path::{
    Path,
    PathBuf,
};

struct Dependency {
    path: PathBuf,
    edges: Vec<usize>,
}

impl Dependency {
    fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            edges: Vec::new(),
        }
    }
}

pub struct DependencyGraph {
    nodes: Vec<Dependency>,
    cursor: usize,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            cursor: 0,
        }
    }

    pub fn add_node<P: AsRef<Path>>(&mut self, path: P) -> usize {
        let mut i = 0;

        while i < self.nodes.len() {
            if self.nodes[i].path.as_path() == path.as_ref() {
                return i;
            }

            i += 1;
        }

        self.nodes.push(Dependency::new(path.as_ref()));
        i
    }

    pub fn add_edge(&mut self, from: usize, to: usize) {
        if !self.nodes[from].edges.contains(&to) {
            self.nodes[from].edges.push(to);
        }
    }

    pub fn next_unvisited(&mut self) -> Option<(usize, &Path)> {
        if self.cursor < self.nodes.len() {
            let ret = Some((self.cursor, self.nodes[self.cursor].path.as_path()));
            self.cursor += 1;
            ret
        } else {
            None
        }
    }

    pub fn walk(&self, start: usize) -> Vec<usize> {
        let mut ret = Vec::<usize>::new();
        let mut cursor = 0;

        ret.push(start);

        while cursor < ret.len() {
            for edge in &self.nodes[ret[cursor]].edges {
                if !ret.contains(edge) {
                    ret.push(*edge);
                }
            }

            cursor += 1;
        }

        ret
    }
}
