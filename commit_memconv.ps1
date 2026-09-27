$ErrorActionPreference = 'Stop'
Set-Location 'C:\Users\fadhi\OneDrive\Documents\AI-DevSecOps-Command-Center'
$realGit = 'C:\Program Files\Git\bin\git.exe'

# Stage and commit
& $realGit add memory/MEMORY.md
$msg = @'
docs(memory): per-agent MEMORY file convention (2026-06-12 racy-write fix)

Lead followup commit capturing the new aionrs auto-memory convention
in the team-level git index. Triggered by PlatformArchitect's EOD
flag that the shared aionrs auto-memory MEMORY.md was being stomped
on by concurrent writes between sessions.

* New convention: per-agent MEMORY files in aionrs auto-memory
  (MEMORY-platform-architect.md, MEMORY-sre.md, etc.)
* No more shared MEMORY.md in aionrs auto-memory
* Team-level index stays in git at memory/MEMORY.md (this file),
  owned by GitOpsManager + Lead
* Root cause: aionrs auto-memory has no concurrent-write isolation
* Out-of-band: the command-code npm shim is the underlying culprit
  (shadows git, breaks on multi-arg calls)

Cross-reference:
* ADR 0014 candidate (Sprint 3 retrospective)
* Spec-vs-review pattern in spec-vs-review-drift-pattern.md
'@
& $realGit commit -m $msg 2>&1
Write-Host ""
Write-Host "=== last commit ==="
& $realGit log -1 --oneline
Write-Host ""
Write-Host "=== pushing ==="
& $realGit push origin main 2>&1
Write-Host "exit: $LASTEXITCODE"
Write-Host ""
Write-Host "=== final status ==="
& $realGit status -sb
Write-Host ""
Write-Host "=== last 3 commits on origin/main ==="
& $realGit log --oneline -3 origin/main
