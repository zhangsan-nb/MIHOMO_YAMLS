# Agent Execution Plan

## Approved policy unit
`{{policy_unit}}`

## User decision
`{{decision}}`

## Desired policy
`{{expected_policy}}`

## Implementation type
`{{implementation_type}}`

## Branch
`{{feature_branch}}`

## Base SHA
`{{base_sha}}`

## Allowed files
{{allowed_files}}

## Forbidden changes

- upstream MRS
- unrelated providers
- publish safety guard
- secrets / real config disclosure
- blanket approval

## Required validation

- local tests relevant to changed code
- Feature CI
- Feature Publish = SKIPPED
- Feature Purge = SKIPPED
- Production branch unchanged

## STOP conditions
{{stop_conditions}}

## After Feature CI PASS
{{next_gate}}

Do not invent additional testing phases without new code or new evidence.
