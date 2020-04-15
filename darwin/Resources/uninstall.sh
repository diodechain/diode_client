#!/bin/bash

# TODO: remove local db and config file

VERSION=__VERSION__

#Check running user
if (( $EUID != 0 )); then
    echo "Please run as root."
    exit
fi

echo "Diode __VERSION__ uninstaller"

while true; do
    read -p "Do you want to continue [Y/n]?" answer
    [[ $answer == "y" || $answer == "Y" || $answer == "" ]] && break
    [[ $answer == "n" || $answer == "N" ]] && exit 0
    echo "Please answer with 'y' or 'n'"
done


find "/usr/local/bin/" -name "diode" | xargs rm
pkgutil --forget "org.Diode.$VERSION" > /dev/null 2>&1
[ -e "/Library/Diode/${VERSION}" ] && rm -rf "/Library/Diode/${VERSION}"

echo "Diode __VERSION__ uninstalled"
exit 0
