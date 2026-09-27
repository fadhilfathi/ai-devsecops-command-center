$ErrorActionPreference = 'Stop'
Set-Location 'C:\Users\fadhi\OneDrive\Documents\AI-DevSecOps-Command-Center'
$realGit = 'C:\Program Files\Git\bin\git.exe'

Write-Host "=== current branch ==="
& $realGit branch --show-current
Write-Host ""
Write-Host "=== all branches ==="
& $realGit branch -vv
Write-Host ""
Write-Host "=== status ==="
& $realGit status -sb
Write-Host ""
Write-Host "=== reflog (last 10) ==="
& $realGit reflog -10
Write-Host ""
Write-Host "=== last 3 commits on hotfix/s2.5-sbom-wire-format-drift ==="
& $realGit log --oneline -3 hotfix/s2.5-sbom-wire-format-drift
Write-Host ""
Write-Host "=== last 3 commits on main ==="
& $realGit log --oneline -3 main
Write-Host ""
Write-Host "=== last 3 commits on origin/main ==="
& $realGit log --oneline -3 origin/main
