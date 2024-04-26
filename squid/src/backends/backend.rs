use crate::{
    event::EventPool,
    frontend::ProcessImage,
    runtime::Runtime,
    Logger,
};

pub trait Backend {
    type Runtime: Runtime;

    fn name(&self) -> String;
    fn create_runtime(&mut self, image: ProcessImage, event_pool: EventPool, logger: &Logger) -> Result<Self::Runtime, String>;
}
