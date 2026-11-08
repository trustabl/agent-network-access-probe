---
description: Check an agent tool with Trustabl Probe (network allow list, runtime problems)
argument-hint: "[tool directory]"
---

Check an agent tool with Trustabl Probe, following the `probe-scan` skill.

Target: `$ARGUMENTS` when given, otherwise the current working directory.

Use the sandbox when Docker is running, else scan static only and say so. Report
the readiness score, the draft network allow list and the findings worst first,
each with its fix hint. Do not change any files in this command: offer to apply
the fixes afterwards.
