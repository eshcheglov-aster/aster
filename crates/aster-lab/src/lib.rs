//! Native mesh and real-process laboratories for Aster Mesh.
//!
//! Gate H evaluates the shared-node native mesh ownership boundary.

#![forbid(unsafe_code)]

pub mod live;
pub mod mesh_experiment;

use std::error::Error;

/// Error result returned by a laboratory scenario.
pub type LabResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
