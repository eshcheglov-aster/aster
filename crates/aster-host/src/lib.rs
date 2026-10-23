//! Process-owned, offline-first composition host for Aster Mesh.
//!
//! [`SharedNodeContactSupervisor`] is the candidate multi-contact ownership
//! boundary evaluated by Gate H.

#![forbid(unsafe_code)]

mod mesh_host;
mod node_admission;
mod node_budget;
mod shared_node;

pub use mesh_host::{
    CandidateId, CandidateLocator, CandidateProvenance, CandidateStatus, CarrierIdentity,
    ContactCloseReason, ContactDirection, ContactId, ContactPath, HostAction, HostConfig,
    HostEvent, HostSnapshot, MeshHost, MeshHostError,
};
pub use node_admission::AdmissionTransactionError;
pub use node_budget::{
    NodeResourceBudget, NodeResourceClaim, NodeResourceLease, NodeResourceLimits,
    NodeResourceSnapshot, ResourceBudgetError,
};
pub use shared_node::{
    AdmissionAbortReason, ContactDriveReport, ContactOpenReport, ContactOpening, ContactPlan,
    ContactResourceClaims, ContactSessionRole, ContactSupervisorConfig, ContactSupervisorError,
    NodeProviderResourceLease, SharedContactStatus, SharedNodeAuthorizationMutation,
    SharedNodeContactSupervisor, SharedNodeEvidenceCounters, SharedNodeEvidenceTransition,
    SharedNodeMutation,
};
