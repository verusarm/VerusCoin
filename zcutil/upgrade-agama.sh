#!/bin/bash
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Removing old binaries"
    rm /Applications/Agama.app/Contents/Resources/app/assets/bin/osx/*
    echo "Copying files"
    cp ./* /Applications/Agama.app/Contents/Resources/app/assets/bin/osx
    echo "Upgrade complete"
else
    echo "Agama directory, followed by [ENTER]:"
    read AGAMA_DIR
    echo "Removing old binaries"
    rm ${AGAMA_DIR}/resources/app/assets/bin/linux64/*
    echo "Copying files"
    cp ./* ${AGAMA_DIR}/resources/app/assets/bin/linux64
    echo "Upgrade complete"
fi
