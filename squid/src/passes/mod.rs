//! Contains the passes that are provided by `squid`

mod asan;
mod breakpoint;
mod dot;
mod pass;
mod verify;

pub use asan::AsanPass;
pub use breakpoint::{
    BreakpointPass,
    BreakpointPassError,
};
pub use dot::{
    FunctionDOTPass,
    ImageDOTPass,
};
pub use pass::{
    NoPassError,
    Pass,
};
pub(crate) use verify::VerifyerPass;
pub use verify::VerifyerPassError;
