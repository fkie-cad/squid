use crate::{
    event::EventPool,
    frontend::ProcessImage,
    runtime::Runtime,
    Logger,
};

/// Any type that implements this trait can be used as a "backend".
/// A backend is responsible for lowering `squid`s IR to native machine code
/// and making the compiled code available to the user in the form of a [`Runtime`].
pub trait Backend {
    /// This is the type of the Runtime created by the backend.
    /// Each backend has its own corresponding runtime.
    type Runtime: Runtime;

    /// This error type can be returned by the backend during its operations.
    type Error: std::error::Error;

    /// The name of the backend (displayed on the terminal)
    fn name(&self) -> String;

    /// This function realizes the main functionality of a backend.
    /// It receives the process image and the event pool and constructs a runtime
    /// that enables a user to execute the code in the process image.
    fn create_runtime(&mut self, image: ProcessImage, event_pool: EventPool, logger: &Logger) -> Result<Self::Runtime, Self::Error>;
}
