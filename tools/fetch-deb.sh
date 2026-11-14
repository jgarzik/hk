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

# The Ubuntu release whose archive is read: UBUNTU_CODENAME, else the
# host's (CI's reference Linux comes from its runner's, e.g. noble)
deb_codename() {
    if [ -n "${UBUNTU_CODENAME:-}" ]; then
        echo "$UBUNTU_CODENAME"
    else
        (. /etc/os-release && echo "$VERSION_CODENAME")
    fi
}

# The verified package index of <deb-arch> (main, universe) into <out>,
# newest pocket first (-updates, -security, release), as apt prefers
archive_index() {
    local arch=$1 out=$2
    local base codename tmp pocket idx sha
    base=$(deb_base "$arch")
    codename=$(deb_codename)
    tmp=$(mktemp -d)
    : > "$out"
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
            xz -dc "$tmp/Packages.xz" >> "$out"
            echo >> "$out"
        done
    done
    rm -rf "$tmp"
    [ -s "$out" ] || {
        echo "fetch-deb: no package index for $codename ($arch)" >&2
        return 1
    }
}

# Field <field> of the first <pkg> stanza (any version when <ver> is
# empty) in index <file>
index_field() {
    local file=$1 pkg=$2 ver=$3 field=$4
    awk -v p="$pkg" -v v="$ver" -v f="$field:" '
        /^Package: /{pk=$2} /^Version: /{vr=$2}
        $1==f {val=$0; sub(/^[^:]*: /, "", val)}
        /^$/{ if (pk==p && (v=="" || vr==v) && val!="") {print val; exit} pk=vr=val="" }' "$file"
}

# The kernel release ("6.8.0-149-generic") and version linux-image-generic
# of the archive's Ubuntu release pulls in for <deb-arch>
archive_kernel() {
    local arch=$1 tmp kver ver
    tmp=$(mktemp)
    archive_index "$arch" "$tmp" || {
        rm -f "$tmp"
        return 1
    }
    kver=$(index_field "$tmp" linux-image-generic "" Depends |
        grep -o 'linux-image-[0-9][^ ,]*-generic' | head -1)
    kver=${kver#linux-image-}
    ver=$(index_field "$tmp" "linux-image-unsigned-$kver" "" Version)
    rm -f "$tmp"
    [ -n "$kver" ] && [ -n "$ver" ] || {
        echo "fetch-deb: no linux-image-generic kernel in $(deb_codename) ($arch)" >&2
        return 1
    }
    echo "$kver $ver"
}

# Download <pkg> <ver> for <deb-arch> from the archive into <out>, verified
fetch_archive_deb() {
    local pkg=$1 ver=$2 arch=$3 out=$4
    local base tmp filename sha
    base=$(deb_base "$arch")
    tmp=$(mktemp -d)
    archive_index "$arch" "$tmp/Packages" || {
        rm -rf "$tmp"
        return 1
    }
    filename=$(index_field "$tmp/Packages" "$pkg" "$ver" Filename)
    sha=$(index_field "$tmp/Packages" "$pkg" "$ver" SHA256)
    if [ -z "$filename" ] || [ -z "$sha" ]; then
        rm -rf "$tmp"
        echo "fetch-deb: $pkg $ver not found in $base ($arch)" >&2
        return 1
    fi
    curl -sSfo "$tmp/pkg.deb" "$base/$filename"
    if ! echo "$sha  $tmp/pkg.deb" | sha256sum -c --quiet; then
        rm -rf "$tmp"
        return 1
    fi
    mv "$tmp/pkg.deb" "$out"
    rm -rf "$tmp"
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
