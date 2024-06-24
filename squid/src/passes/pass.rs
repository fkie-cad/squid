use crate::{
    event::EventPool,
    frontend::ProcessImage,
    logger::Logger,
};

/// A pass in `squid` is any type that implements this trait.
/// 
/// Passes can be used to inspect or modify the process image.
pub trait Pass {
    /// The error that might be returned by the pass
    type Error: std::error::Error;

    /// The name of the pass (displayed on the terminal)
    fn name(&self) -> String;
    
    /// Run the pass.
    /// 
    /// # Arguments
    /// 1. `image`: The process image that contains all code and data of the target application and all its dependencies
    /// 2. `event_pool`: The event pool that manages all events that can be thrown by the application
    /// 3. `logger`: A helper struct that can display log messages at different log levels
    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), Self::Error>;
}
