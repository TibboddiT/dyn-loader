ARG BASE
FROM ${BASE}
ARG SNAPSHOT
# Match the base image's repository date. A current rolling repository could
# replace glibc while installing GCC, invalidating the intended runtime comparison.
RUN printf 'Server = https://archive.archlinux.org/repos/%s/$repo/os/$arch\n' "$SNAPSHOT" > /etc/pacman.d/mirrorlist && \
    pacman -Syu --noconfirm --needed gcc binutils
