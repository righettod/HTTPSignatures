Write-Host "[*] Build extension artifact..." -ForegroundColor DarkYellow
mvn -q package assembly:single
Write-Host "[*] Copy artifact to the BURP extension folder..." -ForegroundColor DarkYellow
Copy-Item -Force -Path ".\target\HTTPSignatures-jar-with-dependencies.jar" -Destination "$env:BURP_LOCALLY_BUILT_EXTENSIONS_HOME\HTTPSignatures.jar"
Write-Host "[V] Extension file updated." -ForegroundColor Green