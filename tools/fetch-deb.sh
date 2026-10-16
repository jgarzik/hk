#!/bin/bash
#
# Verified download of an Ubuntu .deb, for any architecture, without root.
#
# Native architecture: `apt-get download` (apt checks the signed lists).
# Foreign architecture: the Ubuntu archive (amd64) or ports archive (arm64)
# with apt's chain of trust done by hand: InRelease signature (archive
# keyring) -> Packages.xz hash -> .deb hash. Nothing unverified is kept.
#
# Usage (script):  tools/fetch-deb.sh <package> <deb-arch> <out.deb> [version]
# Usage (library): . tools/fetch-deb.sh; fetch_deb <package> <deb-arch> <out.deb> [version]
# The version defaults to apt's candidate for the native architecture
# (Ubuntu builds the same source version for every architecture).

# Archive base URL of a Debian architecture
deb_base() {
    case $1 in
        amd64 | i386) echo https://archive.ubuntu.com/ubuntu ;;
        *) echo https://ports.ubuntu.com/ubuntu-ports ;;
    esac
}

# Download <pkg> <ver> for <deb-arch> from the archive into <out>, verified
fetch_archive_deb() {
    local pkg=$1 ver=$2 arch=$3 out=$4
    local base codename tmp pocket idx filename sha
    base=$(deb_base "$arch")
    codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
    tmp=$(mktemp -d)
    for pocket in "$codename-updates" "$codename-security" "$codename"; do
        curl -sSfo "$tmp/InRelease" "$base/dists/$pocket/InRelease" || continue
        gpgv --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg \
            --output "$tmp/Release" "$tmp/InRelease" 2>/dev/null || {
            echo "fetch-deb: bad InRelease signature ($pocket)" >&2
            rm -rf "$tmp"
            return 1
        }
        for comp in main universe; do
            idx=$comp/binary-$arch/Packages.xz
            sha=$(awk -v f="$idx" '/^SHA256:/{s=1;next} /^[^ ]/{s=0} s && $3==f {print $1}' "$tmp/Release")
            [ -n "$sha" ] || continue
            # By hash: immune to a mirror updating between the two fetches
            curl -sSfo "$tmp/Packages.xz" "$base/dists/$pocket/${idx%/*}/by-hash/SHA256/$sha" ||
                curl -sSfo "$tmp/Packages.xz" "$base/dists/$pocket/$idx" || continue
            echo "$sha  $tmp/Packages.xz" | sha256sum -c --quiet || {
                rm -rf "$tmp"
                return 1
            }
            xz -dc "$tmp/Packages.xz" > "$tmp/Packages"
            filename= sha=
            read -r filename sha < <(awk -v p="$pkg" -v v="$ver" '
                /^Package: /{pk=$2} /^Version: /{vr=$2} /^Filename: /{fn=$2} /^SHA256: /{sh=$2}
                /^$/{ if (pk==p && vr==v) {print fn, sh; exit} pk=vr=fn=sh="" }' "$tmp/Packages") || true
            if [ -n "${filename:-}" ]; then
                curl -sSfo "$tmp/pkg.deb" "$base/$filename"
                if ! echo "$sha  $tmp/pkg.deb" | sha256sum -c --quiet; then
                    rm -rf "$tmp"
                    return 1
                fi
                mv "$tmp/pkg.deb" "$out"
                rm -rf "$tmp"
                return 0
            fi
        done
    done
    rm -rf "$tmp"
    echo "fetch-deb: $pkg $ver not found in $base ($arch)" >&2
    return 1
}

# Fetch <pkg> for <deb-arch> into <out> (verified); [version] optional
fetch_deb() {
    local pkg=$1 arch=$2 out=$3 ver=${4:-}
    local dir
    dir=$(mktemp -d)
    if [ "$arch" = "$(dpkg --print-architecture)" ] && [ -z "$ver" ]; then
        if (cd "$dir" && apt-get download "$pkg" >/dev/null); then
            mv "$dir"/*.deb "$out"
            rm -rf "$dir"
            return 0
        fi
        rm -rf "$dir"
        return 1
    fi
    rm -rf "$dir"
    [ -n "$ver" ] || ver=$(apt-cache show "$pkg" | sed -n 's/^Version: //p' | head -1)
    [ -n "$ver" ] || {
        echo "fetch-deb: no version of $pkg known to apt" >&2
        return 1
    }
    fetch_archive_deb "$pkg" "$ver" "$arch" "$out"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    set -euo pipefail
    [ $# -ge 3 ] || {
        echo "Usage: $0 <package> <deb-arch> <out.deb> [version]" >&2
        exit 1
    }
    fetch_deb "$@"
fi
