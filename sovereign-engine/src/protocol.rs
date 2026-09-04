pub const VERSION: u32 = 1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    Genesis = 0x01,
    Lineage = 0x02,
    CrashReceipt = 0x03,
    PersistenceReceipt = 0x04,
    SealPayload = 0x05,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageStage {
    PreExecutionGuard = 0x0001,
    GuardTimestamp = 0x0002,
    PureStateEvaluator = 0x0003,
    AtomicExecutionOutput = 0x0004,

    CryptographicSealPayload = 0x0005,

    TerminalSafeState = 0x00FD,
    TerminalDenied = 0x00FE,
    TerminalSealed = 0x00FF,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureStage {
    PreExecutionGuard = 0x01,
    PureStateEvaluator = 0x02,
    AtomicExecution = 0x03,
    CryptographicSeal = 0x04,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    CadenceViolation = 0x01,
    IncompleteSpec = 0x02,
    UnsatisfiedDependency = 0x03,
    AtomicExecutionFailure = 0x04,
    UnauthorizedSigningKey = 0x05,
    GuardVerificationFailed = 0x06,
}
