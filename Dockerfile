####################################################
# GOLANG BUILDER
####################################################
FROM golang:1.25-bookworm AS go_builder

# Local ES 8 port of malice-plugins/pkgs. Passed as an additional build
# context: docker build --build-context pkgs=../malice-plugins
COPY --from=pkgs . /build/malice-plugins/
COPY . /build/diec/
WORKDIR /build/diec

# Pure Go (shells out to the diec CLI) -> static binary.
RUN CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w -X main.Version=v$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -o /bin/diec-scan .

####################################################
# DETECT-IT-EASY RUNTIME
####################################################
# ubuntu:20.04 (focal) — the EXACT target the prebuilt diec 3.21 portable
# binary is built for. It links against focal's libicu66 / libdouble-conversion
# / libpcre2-16 sonames; a newer glibc distro would not satisfy ICU 66.
FROM ubuntu:20.04

LABEL maintainer="https://github.com/blacktop"

LABEL malice.plugin.repository="https://github.com/malice-plugins/diec.git"
LABEL malice.plugin.category="exe"
LABEL malice.plugin.mime="*"
LABEL malice.plugin.docker.engine="*"

# Detect-It-Easy v3.21 prebuilt Linux portable (the `diec` CLI). The tarball is
# a native Qt5 C++ build (NOT .NET on Linux); its Qt5 shared libraries are
# bundled under base/. Only focal's system libs are needed from apt.
ENV DIE_VERSION=3.21
ENV DIE_TARBALL=die_3.21_portable_Ubuntu_20.04_amd64.tar.gz
ENV DIE_URL=https://github.com/horsicq/DIE-engine/releases/download/3.21/${DIE_TARBALL}
ENV DIE_SHA256=4d85614dd169c0d23f52084f86e05a503c30429df5fb5ec14de50f23808bc2d4

# System libs diec is linked against (verified via ldd): libicu66,
# libdouble-conversion3, libpcre2-16/8, libglib2.0, libz1, libstdc++6. gosu
# drops privileges to the malice user (matches the other modern engines).
# The tarball is checksum-pinned for reproducibility.
RUN set -eux \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
       ca-certificates curl gosu \
       libicu66 libdouble-conversion3 libpcre2-16-0 libpcre2-8-0 \
       libglib2.0-0 libz1 libstdc++6 \
  && curl -fsSL -o /tmp/die.tar.gz "${DIE_URL}" \
  && echo "${DIE_SHA256}  /tmp/die.tar.gz" | sha256sum -c - \
  && mkdir -p /opt/die \
  && tar xzf /tmp/die.tar.gz -C /opt/die --strip-components=1 \
  && rm -f /tmp/die.tar.gz \
  && test -x /opt/die/base/diec \
  && groupadd -r malice \
  && useradd --no-log-init -r -g malice malice \
  && mkdir -p /malware \
  && chown -R malice:malice /malware \
  && chmod -R a+rX /opt/die \
  && rm -rf /var/lib/apt/lists/*

COPY --from=go_builder /bin/diec-scan /bin/diec-scan

WORKDIR /malware

ENTRYPOINT ["gosu","malice","diec-scan"]
CMD ["--help"]
