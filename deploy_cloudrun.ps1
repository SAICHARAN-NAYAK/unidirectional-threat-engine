# Google Cloud Run Automated Deployment Script
param (
    [string]$ProjectId = "calm-path-482313-d8",
    [string]$Region = "us-central1",
    [string]$ServiceName = "threat-enclave"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " CYBERSHIELD // GOOGLE CLOUD RUN DEPLOYMENT WIZARD" -ForegroundColor Cyan
Write-Host " Target Project : $ProjectId" -ForegroundColor Yellow
Write-Host " Target Region  : $Region" -ForegroundColor Yellow
Write-Host " Service Name   : $ServiceName" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# Locate gcloud.cmd
$gcloudCmd = (Get-Command gcloud.cmd -ErrorAction SilentlyContinue).Source
if (-not $gcloudCmd) {
    $gcloudCmd = "C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"
}

if (-not (Test-Path $gcloudCmd)) {
    Write-Error "Google Cloud SDK (gcloud.cmd) not found on path."
    exit 1
}

Write-Host "[*] Setting active project: $ProjectId..." -ForegroundColor Green
& $gcloudCmd config set project $ProjectId

Write-Host "[*] Enabling required Google Cloud APIs..." -ForegroundColor Green
& $gcloudCmd services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com

Write-Host "[*] Initiating Cloud Run source build and deployment..." -ForegroundColor Green
& $gcloudCmd run deploy $ServiceName `
    --source . `
    --region $Region `
    --platform managed `
    --allow-unauthenticated `
    --port 8080 `
    --cpu 2 `
    --memory 2Gi `
    --set-env-vars HOST=0.0.0.0,PORT=8080

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] Cloud Run Deployment Successful!" -ForegroundColor Green
    $url = & $gcloudCmd run services describe $ServiceName --region $Region --format "value(status.url)"
    Write-Host "[+] Public HTTPS Dashboard URL: $url" -ForegroundColor Cyan
} else {
    Write-Host "`n[!] Deployment encountered an issue. Please verify billing account link on project $ProjectId." -ForegroundColor Red
}
