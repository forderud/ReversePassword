# Script for building and packaging versioned releases of this project.
# Run from "Developer PowerShell for VS 2022" from a commit with a git tag.

# stop script on first error
$ErrorActionPreference = "Stop"

$p = Start-Process -FilePath "git.exe" -ArgumentList "tag --points-at HEAD" -NoNewWindow -Wait -RedirectStandardOutput  "tagname.txt"
$tagname = Get-Content -Path "tagname.txt"
if ($tagname -eq $null) {
    throw "No git tag found for current commit"
}

# Build solution in Release for x64
msbuild /nologo /verbosity:minimal /property:Configuration="Release"`;Platform="x64" ReversePassword.sln
if ($LastExitCode -ne 0) {
    throw "msbuild failure"
}

# Create ZIP archive with binaries
Copy-Item -Path "ReversePassword\bin\Release\net8.0-windows" -Destination "x64\Release"
Compress-Archive -Path "x64\Release" -DestinationPath "ReversePassword-$tagname.zip"
