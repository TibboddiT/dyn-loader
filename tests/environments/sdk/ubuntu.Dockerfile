ARG BASE
FROM ${BASE}
ARG SUITE
ARG SNAPSHOT
ARG LIBC_PACKAGE_VERSION
# The matrix verifies libc/loader hashes against the pinned base image.
# The minimal base lacks the CA bundle required by Ubuntu's HTTPS-only snapshots.
RUN apt-get -o Acquire::Retries=2 update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates && \
    rm -f /etc/apt/sources.list.d/* && \
    printf 'deb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s/ %s main universe\ndeb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s/ %s-updates main universe\ndeb [check-valid-until=no] https://snapshot.ubuntu.com/ubuntu/%s/ %s-security main universe\n' "$SNAPSHOT" "$SUITE" "$SNAPSHOT" "$SUITE" "$SNAPSHOT" "$SUITE" > /etc/apt/sources.list && \
    apt-get -o Acquire::Retries=2 update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc g++ binutils \
        "libc6=$LIBC_PACKAGE_VERSION" "libc6-dev=$LIBC_PACKAGE_VERSION" "libc-dev-bin=$LIBC_PACKAGE_VERSION"
