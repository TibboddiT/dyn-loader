ARG BASE
FROM ${BASE}
ARG LIBC_PACKAGE_VERSION
# Alpine packages can change. Both musl packages use a fixed version.
RUN apk add --no-cache gcc g++ binutils "musl=$LIBC_PACKAGE_VERSION" "musl-dev=$LIBC_PACKAGE_VERSION"
