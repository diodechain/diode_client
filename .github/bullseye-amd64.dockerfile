FROM debian:bullseye

ENV GOOS=linux
ENV CGO_ENABLED=1

RUN apt-get update -y && \
    apt-get install -y git && \
    apt-get install -y build-essential && \
    apt-get install -y pkg-config && \
    apt-get install -y upx && \
    apt-get install -y zip && \
    apt-get install -y wget

# install golang
RUN echo "Build and install golang......"
ENV GOFILE=go1.25.9.linux-amd64.tar.gz
RUN wget https://dl.google.com/go/$GOFILE && \
    [ "00859d7bd6defe8bf84d9db9e57b9a4467b2887c18cd93ae7460e713db774bc1" = "$(sha256sum $GOFILE | cut -d ' ' -f1)" ] && \
    tar -xvf $GOFILE
RUN mv go /usr/local
ENV GOROOT "/usr/local/go"
RUN mkdir /go
ENV GOPATH "/go"
ENV PATH="$GOPATH/bin:$GOROOT/bin:$PATH"

RUN mkdir build
WORKDIR /build

# OpenSSL Settings
RUN mkdir diode_client
WORKDIR /build/diode_client

COPY . .
RUN make openssl
RUN make archive
