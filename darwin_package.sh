#!/bin/bash

# TODO: add config_server in launchpad, and sign the package
DARWIN_DIRECTORY="darwin"
BUILD_DIRECTORY="darwin/build"
BINARY_DIRECTORY="./"
VERSION=`git describe --tags --dirty | awk '{ print substr(\$0, 2) }'`

if [ ! -z $DIODE_DARWIN_SRC ] && [ -d $DIODE_DARWIN_SRC ]; then
    DARWIN_DIRECTORY=$DIODE_DARWIN_SRC
fi

if [ ! -z $DIODE_BUILD_DST ] && [ -d $DIODE_BUILD_DST ]; then
    BUILD_DIRECTORY=$DIODE_BUILD_DST
fi

echo "Diode package builder for macos"

if [ ! -z $DIODE_VERSION ] && [[ $DIODE_VERSION == [0-9].[0-9].[0-9] ]]; then
    VERSION=$DIODE_VERSION
fi

if [ ! -z $DIODE_BINARY_DIRECTORY ] && [ -d $DIODE_BINARY_DIRECTORY ]; then
    BINARY_DIRECTORY=$DIODE_BINARY_DIRECTORY
fi

if [ ! -f $BINARY_DIRECTORY/diode ]; then
    echo "Please make diode first"
    exit 1
fi

if [ ! -f diode ]; then
    echo "Please make diode first"
    exit 1
fi

# clean build
if [ -f $BUILD_DIRECTORY ]; then
    rm -rf $BUILD_DIRECTORY/*
fi

# mkdir dir
if [ ! -d $BUILD_DIRECTORY/package ]; then
    mkdir $BUILD_DIRECTORY/package
fi

if [ ! -d $BUILD_DIRECTORY/darwinpkg ]; then
    mkdir $BUILD_DIRECTORY/darwinpkg
    mkdir $BUILD_DIRECTORY/darwinpkg/Library
    mkdir $BUILD_DIRECTORY/darwinpkg/Library/Diode
    mkdir $BUILD_DIRECTORY/darwinpkg/Library/Diode/$VERSION
fi

# update version
cp $BINARY_DIRECTORY/diode $BUILD_DIRECTORY/darwinpkg/Library/Diode/$VERSION
cp -R $DARWIN_DIRECTORY/Resources $BUILD_DIRECTORY/Resources
chmod -R 755 $BUILD_DIRECTORY
cp -R $DARWIN_DIRECTORY/scripts $BUILD_DIRECTORY/scripts
cp -R $DARWIN_DIRECTORY/Distribution $BUILD_DIRECTORY/Distribution
cp $DARWIN_DIRECTORY/Resources/uninstall.sh $BUILD_DIRECTORY/darwinpkg/Library/Diode/$VERSION
sed -i '' -e "s/__VERSION__/$VERSION/g" $BUILD_DIRECTORY/Resources/*.html
sed -i '' -e "s/__VERSION__/$VERSION/g" $BUILD_DIRECTORY/scripts/postinstall
sed -i '' -e "s/__VERSION__/$VERSION/g" $BUILD_DIRECTORY/Distribution
sed -i '' -e "s/__VERSION__/$VERSION/g" $BUILD_DIRECTORY/darwinpkg/Library/Diode/$VERSION/uninstall.sh

# build package
pkgbuild --identifier org.diode.$VERSION \
    --version $VERSION \
    --scripts $BUILD_DIRECTORY/scripts \
    --root $BUILD_DIRECTORY/darwinpkg \
    $BUILD_DIRECTORY/package/diode.pkg > /dev/null 2>&1

productbuild --distribution $BUILD_DIRECTORY/Distribution \
    --resources $BUILD_DIRECTORY/Resources \
    --package-path $BUILD_DIRECTORY/package \
    $BUILD_DIRECTORY/diode_${VERSION}_darwin.pkg > /dev/null 2>&1

# clean
find $BUILD_DIRECTORY \! -name diode -type d -mindepth 1 -maxdepth 1 | xargs rm -r
rm -rf $BUILD_DIRECTORY/Distribution

echo "Diode package is builded in $BUILD_DIRECTORY"
