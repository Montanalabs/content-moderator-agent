#! VULNERABLE content-moderator-agent — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant moderatePost confidence 70

let raw = fetch<web>
privileged { moderatePost(raw) }  # tainted -> tool: REJECTED
