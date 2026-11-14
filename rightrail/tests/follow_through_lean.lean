/-
Test runner for tests/test_follow_through_lean.py: reads cases from the JSON file named by the first argument, runs
`followThrough` and `correctionFollowUpStatus` on each (and the calendar helpers over a range of days), and prints the results in the Python module's shape.
The rules are the pack's follow-through rules exactly as stored; the records use the Lean field names.
-/
import Lean.Data.Json
import BlindLedger.Financial.FollowThrough

open Lean BlindLedger.Financial.FollowThrough

instance : FromJson ReportLine where
  fromJson? j := return ⟨← j.getObjValAs? String "form", ← j.getObjValAs? (Option String) "line",
    ← j.getObjValAs? String "summary_line"⟩

instance : FromJson Clock where
  fromJson? j := do
    let add ← j.getObjVal? "add"
    let count ← add.getObjValAs? Nat "count"
    let period ← match ← add.getObjValAs? String "unit" with
      | "DAY" => pure (Period.days count)
      | "YEAR" => pure (Period.years count)
      | unit => throw s!"clock unit {unit}"
    let report ← j.getObjVal? "report"
    let report ← match ← report.getObjValAs? String "kind" with
      | "AT_END" => pure Report.atEnd
      | "CMS64_QUARTER" => pure (Report.cms64Quarter (← report.getObjValAs? Nat "due_days")
          (← report.getObjValAs? ReportLine "collected") (← report.getObjValAs? ReportLine "uncollected"))
      | kind => throw s!"report kind {kind}"
    return ⟨← j.getObjValAs? String "clock_id", ← j.getObjValAs? String "citation",
      ← j.getObjValAs? (List String) "anchors", period, report, ← j.getObjValAs? (List String) "satisfied_by"⟩

instance : FromJson Rules where
  fromJson? j := do
    let parties ← (← j.getObjValAs? (List Json) "parties").mapM fun p => return ⟨← p.getObjValAs? String "party_id",
      ← p.getObjValAs? String "party", ← p.getObjValAs? String "kind", ← p.getObjValAs? (List String) "purposes"⟩
    let reasons ← (← j.getObjValAs? (List Json) "closure_reasons").mapM fun r => return ⟨← r.getObjValAs? String
      "reason_code", ← r.getObjValAs? (List String) "requires", ← r.getObjValAs? (List String) "stops"⟩
    let fmap ← (← j.getObjValAs? (Option (List Json)) "fmap_basis_points").mapM fun rows => rows.mapM fun e =>
      return (← e.getObjValAs? String "period_id", ← e.getObjValAs? Nat "basis_points")
    return ⟨parties, ← j.getObjValAs? String "default_owner_id", ← j.getObjValAs? (List Clock) "clocks", reasons, fmap⟩

deriving instance FromJson for Finder, Support, Payment, Evaluation, Suggestion, Decision, Event, Obligation,
  AcceptedBasis, CurrentBasis, ItemEvidence, LaterEvent

def quarterName (q : Quarter) : String := s!"FFY{q.1}Q{q.2}"

def reportJson (q : Quarter) (r : ReportLine) : Json :=
  Json.mkObj [("quarter", quarterName q), ("form", r.form), ("line", toJson r.line), ("summary_line", r.summaryLine)]

def clockStatusName : ClockStatus → String
  | .notAnchored => "NOT_ANCHORED" | .running => "RUNNING" | .missed => "MISSED"
  | .met => "MET" | .metLate => "MET_LATE" | .stopped => "STOPPED"

def clockJson (v : ClockView) : Json :=
  Json.mkObj [("clock_id", v.clockId), ("citation", v.citation),
    ("anchor", match v.anchor with
      | none => Json.null
      | some a => Json.mkObj [("source", a.source), ("at_ms", a.atMs), ("evidence_id", toJson a.evidenceId),
          ("evidence_record_digest", toJson a.recordDigest), ("recorded_at_ms", a.recordedAt),
          ("event_sequence", toJson a.eventSeq)]),
    ("ends_ms", toJson v.endsMs), ("due_ms", toJson v.dueMs),
    ("report", match v.report with | none => Json.null | some (q, r) => reportJson q r),
    ("satisfied", match v.satisfied with
      | none => Json.null
      | some m => Json.mkObj [("source", m.source), ("at_ms", m.atMs), ("evidence_id", toJson m.evidenceId),
          ("evidence_record_digest", toJson m.recordDigest), ("evaluation_id", toJson m.evaluationId)]),
    ("stopped_by", toJson v.stoppedBy), ("status", clockStatusName v.status)]

def suggestionJson (s : Suggestion) : Json :=
  Json.mkObj [("source_id", s.sourceId), ("source_ref", s.sourceRef), ("source_sha256", s.sourceSha256),
    ("suggested_at_ms", s.suggestedAt), ("act", s.act), ("reason_code", toJson s.reasonCode), ("owner_id", toJson s.ownerId)]

def itemJson (i : Item) : Json :=
  Json.mkObj [("item_id", i.itemId), ("obligation_id", i.obligationId),
    ("found", Json.mkObj [("source_owner_id", i.finder.sourceOwnerId), ("source_id", i.finder.sourceId),
      ("party", toJson (i.finderParty.map (·.party))), ("kind", toJson (i.finderParty.map (·.kind))),
      ("manifest_id", i.finder.manifestId), ("registered_at_ms", i.finder.registeredAt),
      ("approved_by", i.finder.approvedBy), ("approval_ref", i.finder.approvalRef)]),
    ("owner", Json.mkObj [("owner_id", toJson i.owner),
      ("basis", if i.ownerDecision.isSome then "DECISION" else "RULES_DEFAULT"), ("decision_id", toJson i.ownerDecision)]),
    ("status", match i.status with | .open => "OPEN" | .satisfied => "SATISFIED" | .closed => "CLOSED"),
    ("principal_cents", i.principalCents), ("open_cents", i.openCents), ("clocks", Json.arr (i.clocks.map clockJson).toArray),
    ("federal_share", match i.federalShare with
      | none => Json.null
      | some s => Json.mkObj [("period_id", s.periodId), ("basis_points", s.basisPoints), ("cents", s.cents)]),
    ("share_parts", Json.arr (i.shareParts.map fun p => Json.mkObj [("clock_id", p.clockId),
      ("principal_cents", p.principalCents), ("cents", p.cents), ("due_ms", p.dueMs),
      ("report", reportJson p.quarter p.report), ("status", match p.status with
        | .due => "DUE" | .missed => "MISSED" | .met => "MET" | .metLate => "MET_LATE")]).toArray),
    ("decisions", Json.arr (i.decisions.map fun d => Json.mkObj [("decision_id", d.decision.decisionId),
      ("act", d.decision.act), ("reason_code", toJson d.decision.reasonCode), ("owner_id", toJson d.decision.ownerId),
      ("suggestion", match d.decision.suggestion with | none => Json.null | some s => suggestionJson s),
      ("agrees_with_suggestion", toJson d.agrees), ("actor_id", d.decision.actorId),
      ("actor_role", d.decision.actorRole), ("decided_at_ms", d.decidedAt), ("event_sequence", d.seq)]).toArray)]

def run (input : Json) : Except String Json := do
  let follow ← (← input.getObjValAs? (List Json) "follow").mapM fun c => do
    let rules ← c.getObjValAs? Rules "rules"
    let now ← c.getObjValAs? Nat "now"
    let items ← (← c.getObjValAs? (List Obligation) "obligations").mapM fun o =>
      let i := followThrough rules o now
      pure (Json.mkObj [("item", itemJson i), ("gaps", toJson i.gaps)])
    pure (Json.arr items.toArray)
  let corrections ← (← input.getObjValAs? (List Json) "corrections").mapM fun c => do
    let (status, changed) := correctionFollowUpStatus (← c.getObjValAs? String "itemId")
      (← c.getObjValAs? String "obligationId") (← c.getObjValAs? (Option AcceptedBasis) "basis")
      (← c.getObjValAs? CurrentBasis "current") (← c.getObjValAs? (List ItemEvidence) "evidence")
      (← c.getObjValAs? (List LaterEvent) "later")
    pure (Json.mkObj [("status", match status with
      | .current => "CURRENT" | .reopened => "REOPENED" | .reviewRequired => "REVIEW_REQUIRED"),
      ("changed", toJson changed)])
  -- "calendar": [first, last] days since 1970; for each day at 12345 ms into it: the quarter (year * 10 + number),
  -- that quarter's end, and the time plus 1 and plus 4 years
  let calendar := match (input.getObjValAs? (List Nat) "calendar").toOption with
    | some [first, last] => (List.range (last + 1 - first)).map fun i =>
        let t := (first + i) * dayMs + 12345
        let q := quarterOf t
        toJson [q.1 * 10 + q.2, quarterEnd q, addPeriod t (.years 1), addPeriod t (.years 4)]
    | _ => []
  return Json.mkObj [("follow", Json.arr follow.toArray), ("corrections", Json.arr corrections.toArray),
    ("calendar", Json.arr calendar.toArray)]

def main (args : List String) : IO UInt32 := do
  match Json.parse (← IO.FS.readFile (args.headD "")) >>= run with
  | .ok out => IO.println out.compress; pure 0
  | .error e => IO.eprintln e; pure 1
