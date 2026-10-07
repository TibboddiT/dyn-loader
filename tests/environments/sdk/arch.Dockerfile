ARG BASE
FROM ${BASE}
ARG SNAPSHOT
RUN printf 'Server = https://archive.archlinux.org/repos/%s/$repo/os/$arch\n' "$SNAPSHOT" > /etc/pacman.d/mirrorlist && \
    pacman -Syu --noconfirm --needed gcc binutils
