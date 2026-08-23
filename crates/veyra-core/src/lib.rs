//! Veyra's trusted, model-independent execution state machine.

mod kernel;
mod planner;
mod state;

pub use kernel::{
    ApprovalOutcome, Kernel, KernelConfig, KernelError, PreviewOutcome, RollbackOutcome,
    RunOutcome, Submission,
};
pub use planner::{
    FixturePlanner, OpenAiCompatiblePlanner, OpenAiPlannerConfig, Planner, PlannerError,
};
pub use state::{StateMachine, TransitionError};
