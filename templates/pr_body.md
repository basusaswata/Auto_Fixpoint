## What was wrong

${what_wrong}

## Why it is real

${why_real}

## What changed

${what_changed}

Files:
${files_changed}

Test added: ${test_added}

## Proof

${checks}

The patch was produced in an isolated sandbox, independently re-reviewed, built and tested, then
signed (Sigstore keyless) by the Fixpoint workflow. The signature was verified before this PR was opened.

---

Requested by @${actor} · [Fixpoint run](${run_url}) · base `${base_sha}`
Skill: `${skill}` from `${skill_version}` · Model: `${model}`

<details><summary>How to respond</summary>

- **Merge** if it is right. Fixpoint records the outcome.
- **Close without merging** if it is wrong. Add a label `fixpoint-reason/<reason>`
  (`false-positive`, `wrong-fix`, `breaks-behaviour`, `accepted-risk`, `duplicate`) or leave a comment
  saying why. Fixpoint will never raise these findings again, and the case feeds its evals.
- **Request a change** by pushing to this branch or reviewing as usual; Fixpoint will not overwrite an open PR.

</details>

${findings_marker}
${meta_marker}
<!-- fixpoint-group: ${group_id} -->
