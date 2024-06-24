//! Contains the [`EventPool`] and other helper structs.

use std::collections::HashMap;

/// The ID of the syscall event is always the same: this value
pub const EVENT_SYSCALL: usize = 0;

/// The ID of the breakpint event is always the same: this value
pub const EVENT_BREAKPOINT: usize = 1;

/// The ID of an event in the [`EventPool`]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub struct EventId(usize);

impl EventId {
    fn new(id: usize) -> Self {
        EventId(id)
    }

    /// Get the ID as a usize
    pub fn id(&self) -> usize {
        self.0
    }
}

/// The EventPool manages all events that might be thrown during emulation of the target program.
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

    /// Given an event name, create a new event ID and return it.
    /// If the event name already exists, the corresponding ID is returned.
    pub fn add_event<S: Into<String> + AsRef<str>>(&mut self, name: S) -> EventId {
        if let Some(id) = self.get_event(name.as_ref()) {
            id
        } else {
            let id = self.next_event();
            self.events.insert(name.into(), id);
            id
        }
    }

    /// Given an event name, return the corresponding event ID
    pub fn get_event<S: AsRef<str>>(&self, name: S) -> Option<EventId> {
        self.events.get(name.as_ref()).copied()
    }

    /// Delete an event from the event pool
    pub fn remove_event<S: AsRef<str>>(&mut self, name: S) -> Option<EventId> {
        self.events.remove(name.as_ref())
    }

    /// Return the total number of events
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Return whether any events have been created
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}
