use std::collections::HashMap;

#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct EventId(usize);

impl EventId {
    fn new(id: usize) -> Self {
        EventId(id)
    }

    pub fn id(&self) -> usize {
        self.0
    }
}

#[derive(Debug)]
pub struct EventPool {
    events: HashMap<String, EventId>,
    cursor: usize,
}

impl EventPool {
    pub(crate) fn new() -> Self {
        Self {
            events: HashMap::new(),
            cursor: 0,
        }
    }

    fn next_event(&mut self) -> EventId {
        let cursor = self.cursor;
        self.cursor = cursor.checked_add(1).expect("Ran out of possible event ids");
        EventId::new(cursor)
    }

    pub fn add_event<S: Into<String> + AsRef<str>>(&mut self, name: S) -> EventId {
        if let Some(id) = self.get_event(name.as_ref()) {
            id
        } else {
            let id = self.next_event();
            self.events.insert(name.into(), id);
            id
        }
    }

    pub fn get_event<S: AsRef<str>>(&self, name: S) -> Option<EventId> {
        self.events.get(name.as_ref()).copied()
    }

    pub fn remove_event<S: AsRef<str>>(&mut self, name: S) -> Option<EventId> {
        self.events.remove(name.as_ref())
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}
