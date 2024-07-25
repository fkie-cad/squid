//! Contains the passes that are provided by `squid`

mod breakpoint;
mod dot;
mod pass;
mod verify;
mod asan;

pub use breakpoint::{
    BreakpointPass,
    BreakpointPassError,
};
pub use dot::{
    FunctionDOTPass,
    ImageDOTPass,
};
pub use pass::{Pass, NoPassError};
pub(crate) use verify::VerifyerPass;
pub use verify::VerifyerPassError;
pub use asan::AsanPass;
