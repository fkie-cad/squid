mod arith;
mod deadcode;
mod empty;
mod metadata;
mod propagate;
mod regcache;
mod relax;
mod symbolize;

pub(crate) use arith::EliminateArithmeticPass;
pub(crate) use deadcode::DeadCodeEliminationPass;
pub(crate) use empty::EliminateEmptyBasicBlocksPass;
pub(crate) use metadata::MetadataPass;
pub(crate) use propagate::AddressPropagationPass;
pub(crate) use regcache::RegisterCachingPass;
pub(crate) use relax::HandleRelaxationPass;
pub(crate) use symbolize::SymbolizerPass;
