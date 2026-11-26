$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not $env:APP_ALICE_PASSWORD -or -not $env:APP_BOB_PASSWORD) {
    throw 'Set APP_ALICE_PASSWORD and APP_BOB_PASSWORD first (at least 12 characters).'
}
$javaCommand = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin/java.exe' } else { 'java' }
if (-not (Test-Path 'target/secure-cloud-storage-0.1.0-SNAPSHOT.jar')) {
    & ./mvnw.cmd package
    if ($LASTEXITCODE -ne 0) { throw 'Maven build failed' }
}
& $javaCommand -jar target/secure-cloud-storage-0.1.0-SNAPSHOT.jar
