FROM debian/eol:bullseye

ENV GOOS=linux
ENV CGO_ENABLED=1

# Bullseye security InRelease expired after LTS. These packages come from main.
RUN set -eux; \
    find /etc/apt -type f \( -name 'sources.list' -o -name '*.list' -o -name '*.sources' \) \
      -exec sed -i '/debian-security/s/^/# /' {} +; \
    apt-get -o Acquire::Check-Valid-Until=false update -y && \
    apt-get install -y git build-essential pkg-config upx zip wget

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
