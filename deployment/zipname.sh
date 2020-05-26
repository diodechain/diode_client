#!/bin/bash
uname_os() {
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case $os in
    mingw*) os="windows" ;;
    msys*) os="windows" ;;
  esac
  echo "${os}"
}
uname_arch() {
  arch=$(uname -m)
  case $arch in
    x86_64) arch="amd64" ;;
    x86) arch="386" ;;
    i686) arch="386" ;;
    i386) arch="386" ;;
    aarch64) arch="arm64" ;;
    armv5*) arch="arm" ;;
    armv6*) arch="arm" ;;
    armv7*) arch="arm" ;;
  esac
  echo ${arch}
}

OS=$(uname_os)
ARCH=$(uname_arch)

echo diode_${OS}_${ARCH}.zip
