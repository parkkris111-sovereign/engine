----------------------- MODULE SovereignEngine -----------------------
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS 
    Epochs,            \* Set of valid epoch identifiers, e.g., 1..3
    Payloads,          \* Set of untrusted payload bytes
    Seeds              \* Set of initial entropy seeds

VARIABLES 
    engineState,       \* "UNINITIALIZED", "IDLE", "SEALED"
    currentEpoch,      \* Integer epoch counter
    residentTermHash,  \* StateHash stored in engine memory (when SEALED)
    persistenceStore,  \* Set of persistent records <<payload, receipt>>
    authorized         \* Safety flag tracking valid transition authorization

vars == <<engineState, currentEpoch, residentTermHash, persistenceStore, authorized>>

(* Cryptographic Hash Abstraction *)
HashGenesis(epoch, seed) == <<"GENESIS", epoch, seed>>
HashTerminal(lineageHash, payload) == <<"TERMINAL", lineageHash, payload>>
ComputeCommitment(termHash, payload) == <<"RECEIPT", termHash, payload>>

(* Init State *)
Init ==
    /\ engineState = "UNINITIALIZED"
    /\ currentEpoch \in Epochs
    /\ residentTermHash = "NONE"
    /\ persistenceStore = {}
    /\ authorized = FALSE

(* Transition 1: Initialize Engine to IDLE state *)
Bootstrap(epoch, seed) ==
    /\ engineState = "UNINITIALIZED"
    /\ currentEpoch' = epoch
    /\ engineState' = "IDLE"
    /\ UNCHANGED <<residentTermHash, persistenceStore, authorized>>

(* Transition 2: Seal Engine and capture terminal anchor *)
Seal(payload, seed) ==
    LET lineage == HashGenesis(currentEpoch, seed)
        termHash == HashTerminal(lineage, payload)
        receipt == ComputeCommitment(termHash, payload)
    IN
        /\ engineState = "IDLE"
        /\ engineState' = "SEALED"
        /\ residentTermHash' = termHash
        /\ persistenceStore' = persistenceStore \cup {<<payload, receipt>>}
        /\ UNCHANGED <<currentEpoch, authorized>>

(* Transition 3: Atomic Rearm *)
Rearm(payload, receipt) ==
    /\ engineState = "SEALED"
    /\ IF receipt = ComputeCommitment(residentTermHash, payload)
       THEN /\ engineState' = "IDLE"
            /\ currentEpoch' = currentEpoch + 1
            /\ residentTermHash' = "NONE"
            /\ authorized' = TRUE
            /\ UNCHANGED persistenceStore
       ELSE /\ UNCHANGED <<engineState, currentEpoch, residentTermHash, persistenceStore>>
            /\ authorized' = FALSE

Next ==
    \E e \in Epochs, s \in Seeds, p \in Payloads, r \in persistenceStore :
        \/ Bootstrap(e, s)
        \/ Seal(p, s)
        \/ Rearm(p, r[2])

-----------------------------------------------------------------------------
(* FORMAL INVARIANTS *)

\* Invariant 1: State Machine Typestate Isolation
TypeOK ==
    /\ engineState \in {"UNINITIALIZED", "IDLE", "SEALED"}
    /\ currentEpoch \in Nat

\* Invariant 2: Terminal State Non-Substitution (No unauthorized epoch increments)
NoStateTampering ==
    (engineState = "SEALED" /\ authorized = FALSE) => (engineState' /= "IDLE")

\* Safety Theorem: Rearm only succeeds if receipt strictly matches resident state anchor
RearmSafety ==
    \A p \in Payloads, r \in persistenceStore :
        (engineState = "SEALED" /\ Rearm(p, r[2])) => (r[2] = ComputeCommitment(residentTermHash, p))

=============================================================================
