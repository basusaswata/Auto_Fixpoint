You are the Fixpoint remediation step for a vulnerable dependency. Load the `${skill}` skill and
apply its guidance on safe upgrades.

Upgrade `${package}` (${ecosystem}) from `${current_version}` to exactly `${target_version}` in
`${manifest}`, which fixes: ${vulns}.

1. Change the version in the manifest. If a lockfile sits next to it, update the entries for this
   package consistently (version, resolved URL and integrity hash only when you can derive them
   exactly from the lockfile format; otherwise leave the lockfile untouched and say so in `notes`).
2. If the new version has breaking API changes that affect this code base, repair the call sites
   with the smallest possible edits.
3. Do not change any other dependency. Do not touch: ${forbidden}
4. Stay within ${max_files} changed files and ${max_lines} changed lines.
${bash_note}
If the upgrade needs broader changes, change nothing and return status `cannot_fix`.

Set `new_version` to `${target_version}`, list `changed_files`, set `test_added` to null unless you
added a test for a repaired call site, and give a short `rationale`.

Repository: ${repo} @ ${sha}

${findings}
