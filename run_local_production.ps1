# Local & LAN Production Host Runner
$env:HOST = "0.0.0.0"
$env:PORT = "8080"
$env:PYTHONUNBUFFERED = "1"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " CYBERSHIELD // PRODUCTION HOST LISTENER" -ForegroundColor Cyan
Write-Host " Binding: http://0.0.0.0:8080 (Accessible via LAN IP & Localhost)" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan

python run_server.py
