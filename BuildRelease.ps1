# Script for building and packaging versioned releases of this project.
# Run from "Developer PowerShell for VS 2022" from a commit with a git tag.

# stop script on first error
$ErrorActionPreference = "Stop"

# Go to script directory
Set-Location $PSScriptRoot

$p = Start-Process -FilePath "git.exe" -ArgumentList "tag --points-at HEAD" -NoNewWindow -Wait -RedirectStandardOutput  "tagname.txt"
$tagname = Get-Content -Path "tagname.txt"

# restore nuget packages
msbuild /nologo /verbosity:minimal /target:restore ReversePassword.sln
if ($LastExitCode -ne 0) {
    throw "msbuild failure"
}

# Build solution in Release for x64
$mode = "Release"
msbuild /nologo /verbosity:minimal /property:Configuration="$mode"`;Platform="x64" ReversePassword.sln
if ($LastExitCode -ne 0) {
    throw "msbuild failure"
}

# Create ZIP archive with binaries
Copy-Item -Path "ReversePassword\bin\$mode\net8.0-windows\*" -Destination "x64\$mode" -Recurse
Compress-Archive -Path "x64\$mode\*" -DestinationPath "ReversePassword-$tagname.zip"
