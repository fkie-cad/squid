use std::path::Path;

use ewe::{
    Listing,
    ListingFunction,
};

use crate::frontend::{
    LoaderError,
    Symbol,
};

pub(crate) struct ListingManager {
    listing: Option<Listing>,
}

impl ListingManager {
    pub(crate) fn new<P: AsRef<Path>>(path: P) -> Self {
        let path = format!("{}.{}", path.as_ref().display(), ewe::EXTENSION);
        let path = Path::new(&path);
        Self {
            listing: if path.exists() { Some(Listing::from_file(path)) } else { None },
        }
    }

    pub(crate) fn have_metadata(&self) -> bool {
        self.listing.is_some()
    }

    pub(crate) fn lookup_symbol(&self, symbol: &Symbol) -> Result<Option<&ListingFunction>, LoaderError> {
        if let Some(listing) = &self.listing {
            let mut funcs = Vec::new();

            for private_name in symbol.private_names() {
                if !funcs.is_empty() {
                    break;
                }

                funcs = listing.match_symbol(private_name.as_str(), Some(symbol.size()), symbol.file());
            }

            for public_name in symbol.public_names() {
                if !funcs.is_empty() {
                    break;
                }

                funcs = listing.match_symbol(public_name.as_str(), Some(symbol.size()), symbol.file());
            }

            match funcs.len() {
                0 => Ok(None),
                1 => Ok(Some(funcs[0])),
                _ => Err(LoaderError::EweError(format!(
                    "Multiple functions in listing for symbol {:#x}",
                    symbol.vaddr()
                ))),
            }
        } else {
            Ok(None)
        }
    }
}
