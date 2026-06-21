# Identity Nexus AI — Phase 1-3 Audit Report

**Generated:** 2026-06-20 19:23 UTC  
**Auditor:** Automated adversarial audit script  
**Scope:** Phases 1 (spec), 2 (data simulation), 3 (identity resolution, graph building, privilege engine)  

---

## Summary

| Total Checks | PASS | WARNING | FAIL |
|---|---|---|---|
| 52 | 52 | 0 | 0 |

> **All checks PASS. No blockers.**

---

## Detailed Results

| Check | Description | Result | Evidence / Numbers | Action Needed |
|---|---|---|---|---|
| 1a | Schema: unified_identities.csv | ✅ PASS | 16 columns match spec | None required |
| 1a | Schema: group_mappings.csv | ✅ PASS | 8 columns match spec | None required |
| 1a | Schema: role_mappings.csv | ✅ PASS | 12 columns match spec | None required |
| 1a | Schema: audit_events.csv | ✅ PASS | 14 columns match spec | None required |
| 1a | Schema: offboarding_records.csv | ✅ PASS | 10 columns match spec | None required |
| 1a | Schema: resource_access_logs.csv | ✅ PASS | 12 columns match spec | None required |
| 1a | Schema: effective_privileges.csv | ✅ PASS | 13 columns match spec | None required |
| 1a | Schema: group_definitions.csv | ✅ PASS | 7 columns match spec | None required |
| 1a | Schema: role_definitions.csv | ✅ PASS | 7 columns match spec | None required |
| 1a | Schema: resource_catalog.csv | ✅ PASS | 5 columns match spec | None required |
| 1a | Schema: ground_truth_labels.csv | ✅ PASS | 5 columns match spec | None required |
| 1b | FK: ep.identity_id -> ui.identity_id | ✅ PASS | Orphan IDs: 0 | None |
| 1b | FK: ep.resource_id -> resource_catalog | ✅ PASS | Orphan resource IDs: 0 | None |
| 1b | FK: rm.role_id -> role_definitions | ✅ PASS | Orphan role IDs: 0 | None required |
| 1b | FK: rm.identity_id -> ui | ✅ PASS | Orphan IDs: 0 | None required |
| 1b | FK: gm.group_id -> group_definitions | ✅ PASS | Orphan group IDs: 0 | None required |
| 1b | FK: gm.identity_id -> ui | ✅ PASS | Orphan IDs: 0 | None required |
| 1b | FK: gd.parent_group_id -> gd.group_id (self-ref) | ✅ PASS | Orphan parent IDs: 0 | None required |
| 1b | FK: rl.identity_id -> ui | ✅ PASS | Orphan IDs: 0 | None required |
| 1b | FK: ae.identity_id -> ui | ✅ PASS | Orphan IDs: 0 | None required |
| 1b | FK: ae.resource_id (non-null) -> resource_catalog | ✅ PASS | Orphan resource IDs: 0 | None required |
| 1b | FK: ob.identity_id -> ui | ✅ PASS | Orphan IDs: 0 | None required |
| 1b | FK: ob.reviewed_by -> ui | ✅ PASS | Orphan IDs: 0 | None required |
| 1b | FK: rm.approver_id -> ui (nullable, Phase 2 addition) | ✅ PASS | Orphan IDs: 0 | None required |
| 1b | FK: rd.resource_ids[] -> resource_catalog | ✅ PASS | Orphan resource IDs: 0 | None required |
| 1c | permission_scope values match data_dictionary.md | ✅ PASS | All scopes documented | None |
| 2a | Canonical identity count == 453 | ✅ PASS | Actual canonical_ids: 453 | None required |
| 2b | Spot-check multi-platform merge: aaron.mitchell@corp.nexusai.com | ✅ PASS | Platforms=['AD', 'AzureAD', 'AWS', 'Okta', 'Salesforce'], canonical_ids=1 (expected 1) | None required |
| 2b | Spot-check multi-platform merge: amanda.dudley@corp.nexusai.com | ✅ PASS | Platforms=['AD', 'AzureAD', 'AWS', 'Okta', 'Salesforce'], canonical_ids=1 (expected 1) | None required |
| 2b | Spot-check multi-platform merge: brian.hernandez@corp.nexusai.com | ✅ PASS | Platforms=['AD', 'AzureAD', 'AWS', 'Okta', 'Salesforce'], canonical_ids=1 (expected 1) | None required |
| 2c | Email column: no case/whitespace variations | ✅ PASS | Unique emails raw=453, normalised=453; rows with case/space issues=0 | None required |
| 2d | No two distinct display_names merged under one canonical_id | ✅ PASS | Canonical IDs with >1 distinct display_name: 0 | None required |
| 3a | Identity node count == 1377 (1 per platform account, correct by design) | ✅ PASS | Identity nodes: 1377. NOTE: Architecture §6 FEDERATES_TO edge explicitly requires multiple Identity nodes per person (cross-platform). Per-platform granularity needed for platform-specific attributes  | None required |
| 3b | No duplicate node IDs | ✅ PASS | Total nodes=1468, unique node IDs=1468 | None required |
| 3c | NESTED_IN edges form a DAG (no cycles) | ✅ PASS | NESTED_IN subgraph is a DAG (14 edges, 0 cycles) | None required |
| 3d | FEDERATES_TO edges: bidirectional (all platform accounts can pivot to peers) | ✅ PASS | 0/390 multi-platform canonical identities have at least one account with no outgoing FEDERATES_TO edges. Expected 0 after bidirectional fix in graph_builder.py. | None required |
| 3e | Edge type conformance (correct source/target node types) | ✅ PASS | All edges connect correct node type pairs | None required |
| 4a | Manual trace: Danielle Johnson AD account privilege correctness | ✅ PASS | Roles: [] │ Expected resources: 0, Actual in ep.csv: 0 │ Missing: 0 │ Extra: 0 | None required |
| 4b | Manual trace: OVERPRIVILEGED AD account (903ed541-3a35-42...) | ✅ PASS | Roles: ['AD-Domain-Admins'] │ Expected: 4 resources, Actual: 4 │ Missing: 0, Extra: 0 | None required |
| 4c | Highest privilege level wins (verified on real multi-path case) | ✅ PASS | identity=3ae0372a-3bfa-4a: 1 resource(s) reachable via multiple roles with conflicting privilege levels — highest privilege correctly preserved in all cases. | None required |
| 4d | Zero-privilege identities investigation (229 identities) | ✅ PASS | Total zero-privilege: 229 / 1377 identities. Platform breakdown: {'Okta': 229}. account_type breakdown: {'human': 218, 'service': 10, 'machine': 1}. Zero-priv with role assignments: 229. Zero-priv wit | None required — by design |
| 5a | ground_truth_labels.csv NOT read in Phase 3 pipeline modules | ✅ PASS | No violations found | None required |
| 6a | ORPHANED_ACCOUNT: AD/AzureAD disabled, cloud platforms active | ✅ PASS | Sample: [('robert.adkins@corp.nexusai.com', np.True_), ('william.peterson@corp.nexusai.', np.True_), ('lindsey.lee@corp.nexusai.com', np.True_)] | None required |
| 6b | OVERPRIVILEGED avg privileges > NORMAL avg privileges | ✅ PASS | OVERPRIVILEGED avg=5.09, NORMAL avg=2.49, ratio=2.04x | None required |
| 6c | LEGITIMATE_EXCEPTION: ticket_id populated in role_mappings | ✅ PASS | LEGITIMATE_EXCEPTION identities: 215 (platform accounts). With role_mappings rows: 215. Identities with >=1 ticket_id on a role: 215. Total role_mappings rows with ticket_id: 215. Sample ticket IDs: [ | None required |
| 7a | Data simulator: same seed (42) produces identical row counts | ✅ PASS | Row count diffs: {'unified_identities.csv': 0, 'group_mappings.csv': 0, 'role_mappings.csv': 0, 'audit_events.csv': 0, 'offboarding_records.csv': 0, 'resource_access_logs.csv': 0} | None required |
| 7b | Graph builder: deterministic given same inputs | ✅ PASS | Run1: 1468 nodes/6264 edges │ Run2: 1468 nodes/6264 edges | None required |
| 8a | Code quality: identity_resolver.py | ✅ PASS | No TODOs, bare excepts, or placeholder pass statements | None required |
| 8a | Code quality: graph_builder.py | ✅ PASS | No TODOs, bare excepts, or placeholder pass statements | None required |
| 8a | Code quality: effective_privilege_engine.py | ✅ PASS | No TODOs, bare excepts, or placeholder pass statements | None required |
| 8a | Code quality: data_simulator.py | ✅ PASS | No TODOs, bare excepts, or placeholder pass statements | None required |
| 8a | Code quality: anomaly_injector.py | ✅ PASS | No TODOs, bare excepts, or placeholder pass statements | None required |

---

## Key Findings

---

## Appendix: Raw Check Results

### 1a: Schema: unified_identities.csv
**Status:** PASS  
**Evidence:** 16 columns match spec  
**Action:** None required  

### 1a: Schema: group_mappings.csv
**Status:** PASS  
**Evidence:** 8 columns match spec  
**Action:** None required  

### 1a: Schema: role_mappings.csv
**Status:** PASS  
**Evidence:** 12 columns match spec  
**Action:** None required  

### 1a: Schema: audit_events.csv
**Status:** PASS  
**Evidence:** 14 columns match spec  
**Action:** None required  

### 1a: Schema: offboarding_records.csv
**Status:** PASS  
**Evidence:** 10 columns match spec  
**Action:** None required  

### 1a: Schema: resource_access_logs.csv
**Status:** PASS  
**Evidence:** 12 columns match spec  
**Action:** None required  

### 1a: Schema: effective_privileges.csv
**Status:** PASS  
**Evidence:** 13 columns match spec  
**Action:** None required  

### 1a: Schema: group_definitions.csv
**Status:** PASS  
**Evidence:** 7 columns match spec  
**Action:** None required  

### 1a: Schema: role_definitions.csv
**Status:** PASS  
**Evidence:** 7 columns match spec  
**Action:** None required  

### 1a: Schema: resource_catalog.csv
**Status:** PASS  
**Evidence:** 5 columns match spec  
**Action:** None required  

### 1a: Schema: ground_truth_labels.csv
**Status:** PASS  
**Evidence:** 5 columns match spec  
**Action:** None required  

### 1b: FK: ep.identity_id -> ui.identity_id
**Status:** PASS  
**Evidence:** Orphan IDs: 0  
**Action:** None  

### 1b: FK: ep.resource_id -> resource_catalog
**Status:** PASS  
**Evidence:** Orphan resource IDs: 0  
**Action:** None  

### 1b: FK: rm.role_id -> role_definitions
**Status:** PASS  
**Evidence:** Orphan role IDs: 0  
**Action:** None required  

### 1b: FK: rm.identity_id -> ui
**Status:** PASS  
**Evidence:** Orphan IDs: 0  
**Action:** None required  

### 1b: FK: gm.group_id -> group_definitions
**Status:** PASS  
**Evidence:** Orphan group IDs: 0  
**Action:** None required  

### 1b: FK: gm.identity_id -> ui
**Status:** PASS  
**Evidence:** Orphan IDs: 0  
**Action:** None required  

### 1b: FK: gd.parent_group_id -> gd.group_id (self-ref)
**Status:** PASS  
**Evidence:** Orphan parent IDs: 0  
**Action:** None required  

### 1b: FK: rl.identity_id -> ui
**Status:** PASS  
**Evidence:** Orphan IDs: 0  
**Action:** None required  

### 1b: FK: ae.identity_id -> ui
**Status:** PASS  
**Evidence:** Orphan IDs: 0  
**Action:** None required  

### 1b: FK: ae.resource_id (non-null) -> resource_catalog
**Status:** PASS  
**Evidence:** Orphan resource IDs: 0  
**Action:** None required  

### 1b: FK: ob.identity_id -> ui
**Status:** PASS  
**Evidence:** Orphan IDs: 0  
**Action:** None required  

### 1b: FK: ob.reviewed_by -> ui
**Status:** PASS  
**Evidence:** Orphan IDs: 0  
**Action:** None required  

### 1b: FK: rm.approver_id -> ui (nullable, Phase 2 addition)
**Status:** PASS  
**Evidence:** Orphan IDs: 0  
**Action:** None required  

### 1b: FK: rd.resource_ids[] -> resource_catalog
**Status:** PASS  
**Evidence:** Orphan resource IDs: 0  
**Action:** None required  

### 1c: permission_scope values match data_dictionary.md
**Status:** PASS  
**Evidence:** All scopes documented  
**Action:** None  

### 2a: Canonical identity count == 453
**Status:** PASS  
**Evidence:** Actual canonical_ids: 453  
**Action:** None required  

### 2b: Spot-check multi-platform merge: aaron.mitchell@corp.nexusai.com
**Status:** PASS  
**Evidence:** Platforms=['AD', 'AzureAD', 'AWS', 'Okta', 'Salesforce'], canonical_ids=1 (expected 1)  
**Action:** None required  

### 2b: Spot-check multi-platform merge: amanda.dudley@corp.nexusai.com
**Status:** PASS  
**Evidence:** Platforms=['AD', 'AzureAD', 'AWS', 'Okta', 'Salesforce'], canonical_ids=1 (expected 1)  
**Action:** None required  

### 2b: Spot-check multi-platform merge: brian.hernandez@corp.nexusai.com
**Status:** PASS  
**Evidence:** Platforms=['AD', 'AzureAD', 'AWS', 'Okta', 'Salesforce'], canonical_ids=1 (expected 1)  
**Action:** None required  

### 2c: Email column: no case/whitespace variations
**Status:** PASS  
**Evidence:** Unique emails raw=453, normalised=453; rows with case/space issues=0  
**Action:** None required  

### 2d: No two distinct display_names merged under one canonical_id
**Status:** PASS  
**Evidence:** Canonical IDs with >1 distinct display_name: 0  
**Action:** None required  

### 3a: Identity node count == 1377 (1 per platform account, correct by design)
**Status:** PASS  
**Evidence:** Identity nodes: 1377. NOTE: Architecture §6 FEDERATES_TO edge explicitly requires multiple Identity nodes per person (cross-platform). Per-platform granularity needed for platform-specific attributes (is_active per platform, last_login per platform). Canonical grouping is represented via canonical_id node attribute, not node count.  
**Action:** None required  

### 3b: No duplicate node IDs
**Status:** PASS  
**Evidence:** Total nodes=1468, unique node IDs=1468  
**Action:** None required  

### 3c: NESTED_IN edges form a DAG (no cycles)
**Status:** PASS  
**Evidence:** NESTED_IN subgraph is a DAG (14 edges, 0 cycles)  
**Action:** None required  

### 3d: FEDERATES_TO edges: bidirectional (all platform accounts can pivot to peers)
**Status:** PASS  
**Evidence:** 0/390 multi-platform canonical identities have at least one account with no outgoing FEDERATES_TO edges. Expected 0 after bidirectional fix in graph_builder.py.  
**Action:** None required  

### 3e: Edge type conformance (correct source/target node types)
**Status:** PASS  
**Evidence:** All edges connect correct node type pairs  
**Action:** None required  

### 4a: Manual trace: Danielle Johnson AD account privilege correctness
**Status:** PASS  
**Evidence:** Roles: [] | Expected resources: 0, Actual in ep.csv: 0 | Missing: 0 | Extra: 0  
**Action:** None required  

### 4b: Manual trace: OVERPRIVILEGED AD account (903ed541-3a35-42...)
**Status:** PASS  
**Evidence:** Roles: ['AD-Domain-Admins'] | Expected: 4 resources, Actual: 4 | Missing: 0, Extra: 0  
**Action:** None required  

### 4c: Highest privilege level wins (verified on real multi-path case)
**Status:** PASS  
**Evidence:** identity=3ae0372a-3bfa-4a: 1 resource(s) reachable via multiple roles with conflicting privilege levels — highest privilege correctly preserved in all cases.  
**Action:** None required  

### 4d: Zero-privilege identities investigation (229 identities)
**Status:** PASS  
**Evidence:** Total zero-privilege: 229 / 1377 identities. Platform breakdown: {'Okta': 229}. account_type breakdown: {'human': 218, 'service': 10, 'machine': 1}. Zero-priv with role assignments: 229. Zero-priv with ONLY empty-resource-list roles: 229. All 229 zero-privilege accounts are explained: Okta-only accounts whose sole role is Okta-Standard-User (permission_scope=read-only, resource_ids=[]) have no accessible resources. This is CORRECT by design — Okta accounts with no group memberships and the default standard role have no effective resource access until they are added to a group or assigned a role with actual resource_ids. BFS traversal correctly finds nothing to reach.  
**Action:** None required — by design  

### 5a: ground_truth_labels.csv NOT read in Phase 3 pipeline modules
**Status:** PASS  
**Evidence:** No violations found  
**Action:** None required  

### 6a: ORPHANED_ACCOUNT: AD/AzureAD disabled, cloud platforms active
**Status:** PASS  
**Evidence:** Sample: [('robert.adkins@corp.nexusai.com', np.True_), ('william.peterson@corp.nexusai.', np.True_), ('lindsey.lee@corp.nexusai.com', np.True_)]  
**Action:** None required  

### 6b: OVERPRIVILEGED avg privileges > NORMAL avg privileges
**Status:** PASS  
**Evidence:** OVERPRIVILEGED avg=5.09, NORMAL avg=2.49, ratio=2.04x  
**Action:** None required  

### 6c: LEGITIMATE_EXCEPTION: ticket_id populated in role_mappings
**Status:** PASS  
**Evidence:** LEGITIMATE_EXCEPTION identities: 215 (platform accounts). With role_mappings rows: 215. Identities with >=1 ticket_id on a role: 215. Total role_mappings rows with ticket_id: 215. Sample ticket IDs: ['TKT-202606-69333', 'TKT-202606-89682', 'TKT-202606-76989']  
**Action:** None required  

### 7a: Data simulator: same seed (42) produces identical row counts
**Status:** PASS  
**Evidence:** Row count diffs: {'unified_identities.csv': 0, 'group_mappings.csv': 0, 'role_mappings.csv': 0, 'audit_events.csv': 0, 'offboarding_records.csv': 0, 'resource_access_logs.csv': 0}  
**Action:** None required  

### 7b: Graph builder: deterministic given same inputs
**Status:** PASS  
**Evidence:** Run1: 1468 nodes/6264 edges | Run2: 1468 nodes/6264 edges  
**Action:** None required  

### 8a: Code quality: identity_resolver.py
**Status:** PASS  
**Evidence:** No TODOs, bare excepts, or placeholder pass statements  
**Action:** None required  

### 8a: Code quality: graph_builder.py
**Status:** PASS  
**Evidence:** No TODOs, bare excepts, or placeholder pass statements  
**Action:** None required  

### 8a: Code quality: effective_privilege_engine.py
**Status:** PASS  
**Evidence:** No TODOs, bare excepts, or placeholder pass statements  
**Action:** None required  

### 8a: Code quality: data_simulator.py
**Status:** PASS  
**Evidence:** No TODOs, bare excepts, or placeholder pass statements  
**Action:** None required  

### 8a: Code quality: anomaly_injector.py
**Status:** PASS  
**Evidence:** No TODOs, bare excepts, or placeholder pass statements  
**Action:** None required  

