ARG BASE
FROM ${BASE}
ARG SUITE
ARG SNAPSHOT
ARG LIBC_PACKAGE_VERSION
RUN rm -f /etc/apt/sources.list.d/* && \
    printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s/ %s main\n' "$SNAPSHOT" "$SUITE" > /etc/apt/sources.list && \
    case "$SUITE" in \
      bullseye) printf 'deb [check-valid-until=no] http://archive.debian.org/debian-security bullseye-security main\n' >> /etc/apt/sources.list ;; \
      bookworm) printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s/ %s-security main\n' "$SNAPSHOT" "$SUITE" >> /etc/apt/sources.list ;; \
    esac && \
    apt-get -o Acquire::Retries=2 update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc g++ binutils \
        "libc6=$LIBC_PACKAGE_VERSION" "libc6-dev=$LIBC_PACKAGE_VERSION" "libc-dev-bin=$LIBC_PACKAGE_VERSION"
