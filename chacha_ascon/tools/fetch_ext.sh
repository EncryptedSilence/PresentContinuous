#!/bin/sh
# Fetch the pinned external sources this subproject builds against into
# third_party/ext (gitignored). Every implementation taken from them is
# checked against the KATs in chacha_ascon/tests before it is benchmarked.
#   ascon-c  (CC0)        -- the designers' Ascon-AEAD128 implementations
#   pyascon  (CC0)        -- independent Python oracle for Ascon
#   openssl  (Apache-2.0) -- CRYPTOGAMS ChaCha20 perlasm (x86_64, ARMv4/NEON)
set -eu
cd "$(dirname "$0")/../../third_party"
mkdir -p ext && cd ext
fetch() { # dir url commit [sparse paths...]
  d=$1; u=$2; c=$3; shift 3
  if [ ! -d "$d/.git" ]; then
    git init -q "$d"; git -C "$d" remote add origin "$u"
    if [ $# -gt 0 ]; then git -C "$d" sparse-checkout set "$@"; fi
  fi
  git -C "$d" fetch -q --depth 1 --filter=blob:none origin "$c"
  git -C "$d" checkout -q FETCH_HEAD
  test "$(git -C "$d" rev-parse HEAD)" = "$c"
}
fetch ascon-c https://github.com/ascon/ascon-c.git 446347f21b209f3921c65ece70027c366cbe1693
fetch pyascon https://github.com/meichlseder/pyascon.git ed24e54abf9507d26fa49b46a56091570c7e743e
fetch openssl https://github.com/openssl/openssl.git e7608cf6cc188fbee3e26ad9648564e39fb51c84 \
  crypto/chacha crypto/perlasm crypto/arm_arch.h include/crypto
echo "external sources at pinned commits"
