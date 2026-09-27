$ErrorActionPreference = 'Stop'
Set-Location 'C:\Users\fadhi\OneDrive\Documents\AI-DevSecOps-Command-Center'
$realGit = 'C:\Program Files\Git\bin\git.exe'

# Step 1: stash the agent's in-flight wire format drift work
Write-Host "=== stash agent's working tree changes ==="
& $realGit stash push -u -m "sbom-agent-wire-format-drift-$(Get-Date -Format yyyyMMdd-HHmmss)" 2>&1
Write-Host ""

# Step 2: switch to main
Write-Host "=== checkout main ==="
& $realGit checkout main 2>&1
Write-Host ""

# Step 3: cherry-pick my MEMORY.md commit (829f55f) onto main
Write-Host "=== cherry-pick 829f55f onto main ==="
& $realGit cherry-pick 829f55f 2>&1
Write-Host ""

# Step 4: push
Write-Host "=== push main ==="
& $realGit push origin main 2>&1
Write-Host "exit: $LASTEXITCODE"
Write-Host ""

# Step 5: switch back to hotfix branch (where the agent's work is)
Write-Host "=== checkout hotfix branch ==="
& $realGit checkout hotfix/s2.5-sbom-wire-format-drift 2>&1
Write-Host ""

# Step 6: pop the stash to restore the agent's working tree
Write-Host "=== stash pop ==="
& $realGit stash pop 2>&1
Write-Host ""

# Step 7: status
Write-Host "=== final status ==="
& $realGit status -sb
Write-Host ""
Write-Host "=== ahead/behind main and origin/main ==="
& $realGit rev-list --left-right --count origin/main...HEAD
Write-Host ""
Write-Host "=== last 3 commits on origin/main ==="
& $realGit log --oneline -3 origin/main
