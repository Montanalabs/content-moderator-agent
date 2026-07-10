#! Content-moderator agent — untrusted a post can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires moderatePost — the content-moderator agent sink
#! @effect io
#! @confidence 70
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant moderatePost confidence 70

type ModAction = ApproveMod | AgeGate | WarnMod
type Decision = ModPost(ModAction) | RemoveMod

let raw = fetch<web>  # UNTRUSTED a post — tainted
quarantined { let d = extract<Decision>(raw) confidence 70 }  # only a fixed Decision (payloads too) crosses
privileged { moderatePost(d) }  # act on the trusted decision only
