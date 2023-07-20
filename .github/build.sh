#!/bin/bash
export DOCKER_DEFAULT_PLATFORM=linux/amd64
docker build -t pi-arm32 -f pi-arm32.dockerfile .. && \
    docker run --rm --entrypoint cat pi-arm32 /build/diode_client/diode_linux_amd64.zip > diode_linux_arm.zip && \
    docker build -t pi-arm64 -f pi-arm64.dockerfile .. && \
    docker run --rm --entrypoint cat pi-arm64 /build/diode_client/diode_linux_amd64.zip > diode_linux_arm64.zip
