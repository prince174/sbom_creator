"""Experimental raw-POM scope gate; never a direct-dependency classifier."""
from audit_maven_declarations import declarations


def scope_candidates(raw):
    model = declarations(raw)
    blockers = []
    for field in ("parent_present", "profile_count", "management_entries", "modules"):
        if model[field]:
            blockers.append(field)
    rows = []
    for dependency in model["dependencies"]:
        reason = ",".join(blockers)
        scope = dependency["scope"] or "compile"
        if not reason and dependency["property_expression"]:
            reason = "unresolved_expression"
        if not reason and scope not in ("compile", "runtime", "test", "provided"):
            reason = "unsupported_scope"
        status = "UNKNOWN" if reason else (
            "RUNTIME_SCOPE_CANDIDATE" if scope in ("compile", "runtime") else "NON_RUNTIME_SCOPE"
        )
        rows.append({"group": dependency["groupId"], "name": dependency["artifactId"],
                     "status": status, "reason": reason or "standalone_raw_scope",
                     "effective_scope": None if reason else scope,
                     "direct_edge_proven": False, "build_usage_proven": False})
    return {"stage": "scope-gate-only", "rows": rows, "model_blockers": blockers,
            "direct_edges": [], "accuracy_measured": False}
