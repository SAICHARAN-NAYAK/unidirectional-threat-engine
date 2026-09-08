# Automated GitHub Remote Setup & Push Script
param (
    [string]$RepoUrl = ""
)

if (-not $RepoUrl) {
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host " CYBERSHIELD // GITHUB PUSH WIZARD" -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "1. Make sure you have created an empty repository on GitHub:" -ForegroundColor Yellow
    Write-Host "   https://github.com/new" -ForegroundColor White
    Write-Host "   (e.g., repository name: unidirectional-threat-engine)`n" -ForegroundColor White

    $RepoUrl = Read-Host "Enter your GitHub repository URL (HTTPS or SSH)"
}

if (-not $RepoUrl) {
    Write-Error "No repository URL provided. Aborting."
    exit 1
}

Write-Host "`n[*] Configuring remote 'origin' -> $RepoUrl..." -ForegroundColor Green
git remote remove origin 2>$null
git remote add origin $RepoUrl

Write-Host "[*] Renaming branch to main..." -ForegroundColor Green
git branch -M main

Write-Host "[*] Pushing branch 'main' to origin..." -ForegroundColor Green
git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] Successfully pushed code to GitHub: $RepoUrl" -ForegroundColor Green
} else {
    Write-Host "`n[!] Push failed. Please verify your authentication (PAT or SSH key) and repository permissions." -ForegroundColor Red
}
