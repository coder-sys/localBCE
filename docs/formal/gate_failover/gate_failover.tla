--------------------------- MODULE gate_failover ---------------------------
(***************************************************************************)
(* Blind Ledger payment gate: one primary, one fenced synchronous standby, *)
(* a fencer that owns the writer epoch, and a payer that releases money    *)
(* only on a valid ALLOW token or under a logged emergency bypass.         *)
(*                                                                         *)
(* Abstractions (see gate-design.md section e):                            *)
(*  - decision id = payment (one decision per payment; determination       *)
(*    revisions get their own decision id and are not modelled);          *)
(*  - "HOLD" stands for every non-ALLOW outcome;                           *)
(*  - signatures are unforgeable: only EmitToken adds to `tokens`;         *)
(*  - token expiry, checkpoints and the witness are omitted (expiry only   *)
(*    narrows acceptance, so safety is unaffected);                        *)
(*  - a node's log is durable across Crash.                                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Nodes, Payments, MaxEpoch, NoNode

ASSUME /\ MaxEpoch \in Nat \ {0}
       /\ NoNode \notin Nodes
       /\ Cardinality(Nodes) >= 2

Outcomes == {"ALLOW", "HOLD"}
Epochs   == 1..MaxEpoch
NoneOut  == "none"

VARIABLES
  gen,        \* fencer's current writer epoch (latest signed epoch cert)
  prim,       \* primary designated for gen
  stby,       \* in-sync standby designated for gen, or NoNode
  soloEpoch,  \* epoch in which the fencer let prim run without a standby; 0 = none
  role,       \* role[n] \in {"P","S","X"}; a fenced node may still believe "P"
  nodeEpoch,  \* epoch at which node n last joined
  dlog,       \* dlog[n][p]: node n's durable decision for payment p
  tokens,     \* every token ever signed
  fence,      \* payer's highest verified epoch
  released,   \* payer release records
  bypassOn,   \* an emergency bypass grant is active
  bypassLog,  \* payments released under a bypass
  reconciled  \* bypassed payments re-decided after the fact

vars == <<gen, prim, stby, soloEpoch, role, nodeEpoch, dlog, tokens, fence,
          released, bypassOn, bypassLog, reconciled>>

gateVars  == <<gen, prim, stby, soloEpoch, role, nodeEpoch, dlog, tokens>>
payerVars == <<fence, released, bypassOn, bypassLog, reconciled>>

Token   == [pay : Payments, out : Outcomes, ep : Epochs]
Release == [pay : Payments, via : {"TOKEN", "BYPASS"}, ep : 0..MaxEpoch,
            fenceAt : 0..MaxEpoch]

ReleasedPays == {r.pay : r \in released}

TypeOK ==
  /\ gen \in Epochs
  /\ prim \in Nodes
  /\ stby \in Nodes \cup {NoNode}
  /\ soloEpoch \in 0..MaxEpoch
  /\ role \in [Nodes -> {"P", "S", "X"}]
  /\ nodeEpoch \in [Nodes -> 0..MaxEpoch]
  /\ dlog \in [Nodes -> [Payments -> Outcomes \cup {NoneOut}]]
  /\ tokens \subseteq Token
  /\ fence \in Epochs
  /\ released \subseteq Release
  /\ bypassOn \in BOOLEAN
  /\ bypassLog \subseteq Payments
  /\ reconciled \subseteq bypassLog

Init ==
  /\ gen = 1
  /\ prim \in Nodes
  /\ stby \in Nodes \ {prim}
  /\ soloEpoch = 0
  /\ role = [n \in Nodes |-> IF n = prim THEN "P"
                              ELSE IF n = stby THEN "S" ELSE "X"]
  /\ nodeEpoch = [n \in Nodes |-> IF n \in {prim, stby} THEN 1 ELSE 0]
  /\ dlog = [n \in Nodes |-> [p \in Payments |-> NoneOut]]
  /\ tokens = {}
  /\ fence = 1
  /\ released = {}
  /\ bypassOn = FALSE
  /\ bypassLog = {}
  /\ reconciled = {}

-----------------------------------------------------------------------------
(* Gate nodes *)

\* Lean decides. Any node that believes it is primary writes its own log;
\* a fenced primary's writes are harmless because it cannot get them acked.
Decide(n, p, o) ==
  /\ role[n] = "P"
  /\ dlog[n][p] = NoneOut
  /\ dlog' = [dlog EXCEPT ![n][p] = o]
  /\ UNCHANGED <<gen, prim, stby, soloEpoch, role, nodeEpoch, tokens>>
  /\ UNCHANGED payerVars

\* Synchronous replication: a standby acks only writes from its own epoch.
Replicate(n, m, p) ==
  /\ role[n] = "P"
  /\ role[m] = "S"
  /\ nodeEpoch[m] = nodeEpoch[n]
  /\ dlog[n][p] # NoneOut
  /\ dlog[m][p] = NoneOut
  /\ dlog' = [dlog EXCEPT ![m][p] = dlog[n][p]]
  /\ UNCHANGED <<gen, prim, stby, soloEpoch, role, nodeEpoch, tokens>>
  /\ UNCHANGED payerVars

\* A token is signed only after the decision is durable on the standby of the
\* signer's own epoch, or while the fencer has granted solo mode for that epoch.
EmitToken(n, p) ==
  /\ role[n] = "P"
  /\ dlog[n][p] # NoneOut
  /\ \/ \E m \in Nodes \ {n} : /\ role[m] = "S"
                              /\ nodeEpoch[m] = nodeEpoch[n]
                              /\ dlog[m][p] = dlog[n][p]
     \/ nodeEpoch[n] = soloEpoch
  /\ tokens' = tokens \cup {[pay |-> p, out |-> dlog[n][p], ep |-> nodeEpoch[n]]}
  /\ UNCHANGED <<gen, prim, stby, soloEpoch, role, nodeEpoch, dlog>>
  /\ UNCHANGED payerVars

Crash(n) ==
  /\ role[n] # "X"
  /\ role' = [role EXCEPT ![n] = "X"]
  /\ stby' = IF n = stby THEN NoNode ELSE stby
  /\ UNCHANGED <<gen, prim, soloEpoch, nodeEpoch, dlog, tokens>>
  /\ UNCHANGED payerVars

\* The designated primary restarts from its durable log.
Restart(n) ==
  /\ n = prim
  /\ role[n] = "X"
  /\ role' = [role EXCEPT ![n] = "P"]
  /\ UNCHANGED <<gen, prim, stby, soloEpoch, nodeEpoch, dlog, tokens>>
  /\ UNCHANGED payerVars

\* Any other node becomes the standby by copying the live primary's log
\* (its own unacked tail is discarded). Solo mode ends here.
Rejoin(n) ==
  /\ n # prim
  /\ stby = NoNode
  /\ role[prim] = "P"
  /\ stby' = n
  /\ soloEpoch' = 0
  /\ role' = [role EXCEPT ![n] = "S"]
  /\ nodeEpoch' = [nodeEpoch EXCEPT ![n] = gen]
  /\ dlog' = [dlog EXCEPT ![n] = dlog[prim]]
  /\ UNCHANGED <<gen, prim, tokens>>
  /\ UNCHANGED payerVars

-----------------------------------------------------------------------------
(* Fencer: the only writer of the epoch. Each step signs a new epoch cert   *)
(* and retires the previous epoch's signing key.                           *)

\* Promote the in-sync standby. The old primary is not told; it is fenced.
Promote ==
  /\ stby # NoNode
  /\ gen < MaxEpoch
  /\ gen' = gen + 1
  /\ prim' = stby
  /\ stby' = NoNode
  /\ role' = [role EXCEPT ![stby] = "P"]
  /\ nodeEpoch' = [nodeEpoch EXCEPT ![stby] = gen + 1]
  /\ UNCHANGED <<soloEpoch, dlog, tokens>>
  /\ UNCHANGED payerVars

\* Standby lost or partitioned: move the live primary to a new epoch alone,
\* so the old standby can never ack or be promoted.
GoSolo ==
  /\ role[prim] = "P"
  /\ gen < MaxEpoch
  /\ gen' = gen + 1
  /\ stby' = NoNode
  /\ soloEpoch' = gen + 1
  /\ nodeEpoch' = [nodeEpoch EXCEPT ![prim] = gen + 1]
  /\ UNCHANGED <<prim, role, dlog, tokens>>
  /\ UNCHANGED payerVars

-----------------------------------------------------------------------------
(* Payer: the state's payment system. RightRail never moves money.         *)

\* Payer fetches the latest signed epoch cert.
PayerLearnFence ==
  /\ fence < gen
  /\ fence' = gen
  /\ UNCHANGED gateVars
  /\ UNCHANGED <<released, bypassOn, bypassLog, reconciled>>

\* Release on a valid ALLOW token whose epoch is not fenced; a newer epoch in
\* a verified token raises the fence. Exactly once per payment.
PayerRelease(t) ==
  /\ t \in tokens
  /\ t.out = "ALLOW"
  /\ t.ep >= fence
  /\ t.pay \notin ReleasedPays
  /\ released' = released \cup
       {[pay |-> t.pay, via |-> "TOKEN", ep |-> t.ep, fenceAt |-> fence]}
  /\ fence' = t.ep
  /\ UNCHANGED gateVars
  /\ UNCHANGED <<bypassOn, bypassLog, reconciled>>

\* Two state officials sign a bypass grant; it expires automatically.
GrantBypass ==
  /\ ~bypassOn
  /\ bypassOn' = TRUE
  /\ UNCHANGED gateVars
  /\ UNCHANGED <<fence, released, bypassLog, reconciled>>

ExpireBypass ==
  /\ bypassOn
  /\ bypassOn' = FALSE
  /\ UNCHANGED gateVars
  /\ UNCHANGED <<fence, released, bypassLog, reconciled>>

BypassRelease(p) ==
  /\ bypassOn
  /\ p \notin ReleasedPays
  /\ released' = released \cup
       {[pay |-> p, via |-> "BYPASS", ep |-> 0, fenceAt |-> fence]}
  /\ bypassLog' = bypassLog \cup {p}
  /\ UNCHANGED gateVars
  /\ UNCHANGED <<fence, bypassOn, reconciled>>

\* The live primary re-decides a bypassed payment post hoc (a non-ALLOW
\* result becomes a recovery case); modelled as discharging the obligation.
Reconcile(p) ==
  /\ p \in bypassLog \ reconciled
  /\ role[prim] = "P"
  /\ reconciled' = reconciled \cup {p}
  /\ UNCHANGED gateVars
  /\ UNCHANGED <<fence, released, bypassOn, bypassLog>>

-----------------------------------------------------------------------------
Next ==
  \/ \E n \in Nodes, p \in Payments, o \in Outcomes : Decide(n, p, o)
  \/ \E n, m \in Nodes, p \in Payments : Replicate(n, m, p)
  \/ \E n \in Nodes, p \in Payments : EmitToken(n, p)
  \/ \E n \in Nodes : Crash(n) \/ Restart(n) \/ Rejoin(n)
  \/ Promote
  \/ GoSolo
  \/ PayerLearnFence
  \/ \E t \in tokens : PayerRelease(t)
  \/ GrantBypass
  \/ ExpireBypass
  \/ \E p \in Payments : BypassRelease(p) \/ Reconcile(p)

\* A crashed primary is eventually restarted; a bypass eventually expires;
\* reconciliation runs whenever the primary is up infinitely often.
Fairness ==
  /\ WF_vars(\E n \in Nodes : Restart(n))
  /\ WF_vars(ExpireBypass)
  /\ \A p \in Payments : SF_vars(Reconcile(p))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
(* Safety invariants *)

\* 1. No two valid tokens for the same decision carry different outcomes.
NoConflictingTokens ==
  \A t1, t2 \in tokens : t1.pay = t2.pay => t1.out = t2.out

\* 2. No token from a fenced epoch is accepted.
NoFencedTokenAccepted ==
  \A r \in released : r.via = "TOKEN" => r.ep >= r.fenceAt

\* 3. No payment is released without a valid ALLOW token or a logged bypass.
ReleaseRequiresTokenOrBypass ==
  \A r \in released :
     \/ /\ r.via = "TOKEN"
        /\ [pay |-> r.pay, out |-> "ALLOW", ep |-> r.ep] \in tokens
     \/ /\ r.via = "BYPASS"
        /\ r.pay \in bypassLog

\* Supporting invariants.
AtMostOnceRelease ==
  \A r1, r2 \in released : r1.pay = r2.pay => r1 = r2

\* RPO = 0: every signed decision is in the designated primary's log.
NoLostDecision ==
  \A t \in tokens : dlog[prim][t.pay] = t.out

-----------------------------------------------------------------------------
(* Temporal properties *)

\* A fenced primary cannot sign: every new token carries the current epoch.
StaleCannotSign ==
  [][\A t \in tokens' \ tokens : t.ep = gen]_vars

EpochMonotone ==
  [][/\ gen' >= gen
     /\ fence' >= fence
     /\ \A n \in Nodes : nodeEpoch'[n] >= nodeEpoch[n]]_vars

\* 4. Every bypassed payment is eventually reconciled.
BypassEventuallyReconciled ==
  \A p \in Payments : (p \in bypassLog) ~> (p \in reconciled)

=============================================================================
