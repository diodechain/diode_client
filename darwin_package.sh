#!/bin/bash

# TODO: add config_server in launchpad, and sign the package
DARWIN_DIRECTORY="darwin"
BUILD_DIRECTORY="build"
VERSION=${1}

echo "Diode package builder for macos"

if [[ $VERSION != [0-9].[0-9].[0-9] ]]; then
    echo "Please enter a valid version"
    exit 1
fi

if [ ! -f diode ]; then
    echo "Please make diode first"
    exit 1
fi

# clean build
if [ -d ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY} ]; then
    rm -rf ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/*
fi

# mkdir dir
if [ ! -d ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/package ]; then
    mkdir ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/package
fi

if [ ! -d ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg ]; then
    mkdir ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg
    mkdir ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg/Library
    mkdir ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg/Library/Diode
    mkdir ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg/Library/Diode/${VERSION}
fi

# update version
cp diode ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg/Library/Diode/${VERSION}
cp -R ${DARWIN_DIRECTORY}/Resources ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/Resources
cp -R ${DARWIN_DIRECTORY}/scripts ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/scripts
cp -R ${DARWIN_DIRECTORY}/Distribution ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/Distribution
cp ${DARWIN_DIRECTORY}/Resources/uninstall.sh ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg/Library/Diode/${VERSION}
sed -i '' -e "s/__VERSION__/${VERSION}/g" ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/Resources/*.html
sed -i '' -e "s/__VERSION__/${VERSION}/g" ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/scripts/postinstall
sed -i '' -e "s/__VERSION__/${VERSION}/g" ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/Distribution
sed -i '' -e "s/__VERSION__/${VERSION}/g" ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg/Library/Diode/${VERSION}/uninstall.sh

# build package
pkgbuild --identifier org.diode.${VERSION} \
    --version ${VERSION} \
    --scripts ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/scripts \
    --root ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/darwinpkg \
    ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/package/diode.pkg > /dev/null 2>&1

productbuild --distribution ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/Distribution \
    --resources ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/Resources \
    --package-path ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/package \
    ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/diode_${VERSION}_darwin.pkg > /dev/null 2>&1

# clean
find ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY} \! -name diode -type d -mindepth 1 -maxdepth 1 | xargs rm -r
rm -rf ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}/Distribution

echo "Diode package is builded in ${DARWIN_DIRECTORY}/${BUILD_DIRECTORY}"