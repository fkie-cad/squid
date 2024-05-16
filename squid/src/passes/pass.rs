use crate::{
    event::EventPool,
    frontend::ProcessImage,
    logger::Logger,
};

pub trait Pass {
    type Error: std::error::Error;

    fn name(&self) -> String;
    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), Self::Error>;
}
