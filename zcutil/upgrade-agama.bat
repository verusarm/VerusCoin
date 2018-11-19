@echo off
set /p AGAMA_DIR="Agama directory, followed by [ENTER]:"
cd C:\%UserInputPath%
echo "Removing old binaries"
rm %AGAMA_DIR%/resources/app/assets/bin/win64/*
echo "Copying files"
cp ./* %AGAMA_DIR%/resources/app/assets/bin/win64
echo "Upgrade complete"