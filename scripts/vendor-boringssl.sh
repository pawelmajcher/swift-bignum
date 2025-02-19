#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##
# This was substantially adapted from grpc-swift's vendor-boringssl.sh script.
# The license for the original work is reproduced below. See NOTICES.txt for
# more.
#
# Copyright 2016, gRPC Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script creates a vendored copy of BoringSSL that is
# suitable for building with the Swift Package Manager.
#
# Usage:
#   1. Run this script in the package root. It will place
#      a local copy of the BoringSSL sources in Sources/CBigNumBoringSSL.
#      Any prior contents of Sources/CBigNumBoringSSL will be deleted.
#
set -eu

HERE=$(pwd)
DSTROOT=Sources/CBigNumBoringSSL
TMPDIR="${HERE}/.boringssl"
SRCROOT="${TMPDIR}/src/boringssl.googlesource.com/boringssl"

# This function namespaces the awkward inline functions declared in OpenSSL
# and BoringSSL.
function namespace_inlines {
    echo "NAMESPACE inlines"
    # Pull out all STACK_OF functions.
    STACKS=$(grep --no-filename -rE -e "DEFINE_(SPECIAL_)?STACK_OF\([A-Z_0-9a-z]+\)" -e "DEFINE_NAMED_STACK_OF\([A-Z_0-9a-z]+, +[A-Z_0-9a-z:]+\)" "$1/crypto/"* | grep -v '//' | grep -v '#' | gsed -e 's/DEFINE_\(SPECIAL_\)\?STACK_OF(\(.*\))/\2/' -e 's/DEFINE_NAMED_STACK_OF(\(.*\), .*)/\1/')
    STACK_FUNCTIONS=("call_free_func" "call_copy_func" "call_cmp_func" "new" "new_null" "num" "zero" "value" "set" "free" "pop_free" "insert" "delete" "delete_ptr" "find" "shift" "push" "pop" "dup" "sort" "is_sorted" "set_cmp_func" "deep_copy")

    for s in $STACKS; do
        for f in "${STACK_FUNCTIONS[@]}"; do
            echo "#define sk_${s}_${f} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, sk_${s}_${f})" >> "$1/include/openssl/boringssl_prefix_symbols.h"
        done
    done

    # Now pull out all LHASH_OF functions.
    LHASHES=$(grep --no-filename -rE "DEFINE_LHASH_OF\([A-Z_0-9a-z]+\)" "$1/crypto/"* | grep -v '//' | grep -v '#' | grep -v '\\$' | gsed 's/DEFINE_LHASH_OF(\(.*\))/\1/')
    LHASH_FUNCTIONS=("call_cmp_func" "call_hash_func" "new" "free" "num_items" "retrieve" "call_cmp_key" "retrieve_key" "insert" "delete" "call_doall" "call_doall_arg" "doall" "doall_arg")

    for l in $LHASHES; do
        for f in "${LHASH_FUNCTIONS[@]}"; do
            echo "#define lh_${l}_${f} BORINGSSL_ADD_PREFIX(BORINGSSL_PREFIX, lh_${l}_${f})" >> "$1/include/openssl/boringssl_prefix_symbols.h"
        done
    done
}


# This function handles mangling the symbols in BoringSSL.
function mangle_symbols {
    echo "GENERATING mangled symbol list"
    (
        # We need a .a: may as well get SwiftPM to give it to us.
        # Temporarily enable the product we need.
        $sed -i -e 's/MANGLE_START/MANGLE_START*\//' -e 's/MANGLE_END/\/*MANGLE_END/' "${HERE}/Package.swift"

        export GOPATH="${TMPDIR}"

        # Begin by building for macOS. We build for two target triples, Intel
        # and Apple Silicon.
        echo "BUILDING for macOS x86_64"
        swift build --triple "x86_64-apple-macosx" --product CBigNumBoringSSL

        echo "BUILDING for macOS arm64"
        swift build --triple "arm64-apple-macosx" --product CBigNumBoringSSL
        (
            cd "${SRCROOT}"
            echo "GENERATE symbol mangles for macOS"

            go mod tidy -modcacherw
            go run "util/read_symbols.go" -out "${TMPDIR}/symbols-macOS-intel.txt" "${HERE}/.build/x86_64-apple-macosx/debug/libCBigNumBoringSSL.a"
            go run "util/read_symbols.go" -out "${TMPDIR}/symbols-macOS-as.txt" "${HERE}/.build/arm64-apple-macosx/debug/libCBigNumBoringSSL.a"
        )

        if [ -n "$IOS_BUILD_INCLUDED" ]; then
            # Now build for iOS. We use xcodebuild for this because SwiftPM doesn't
            # meaningfully support it. Unfortunately we must archive ourselves.
            xcodebuild -sdk iphoneos -scheme CBigNumBoringSSL -derivedDataPath "${TMPDIR}/iphoneos-deriveddata" -destination generic/platform=iOS
            ar -r "${TMPDIR}/libCBigNumBoringSSL-ios.a" "${TMPDIR}/iphoneos-deriveddata/Build/Products/Debug-iphoneos/libCBigNumBoringSSL.o"
            (
                cd "${SRCROOT}"
                go run "util/read_symbols.go" -out "${TMPDIR}/symbols-iOS.txt" "${TMPDIR}/libCBigNumBoringSSL-ios.a"
            )
        fi

        # Now cross compile for our targets.
        if [ -n "$LINUX_BUILD_INCLUDED" ]; then
            echo "BUILDING for Linux arm64"
            docker run -t -i --rm --privileged -v"$(pwd)":/src -w/src --platform linux/arm64 swift:6.0.3-jammy \
                swift build --product CBigNumBoringSSL
        
            echo "BUILDING for Linux amd64"
            docker run -t -i --rm --privileged -v"$(pwd)":/src -w/src --platform linux/amd64 swift:6.0.3-jammy \
                swift build --product CBigNumBoringSSL

            # Now we need to generate symbol mangles for Linux. We can do this in
            # one go for all of them.
            echo "GENERATE symbol mangles for Linux"
            (
                cd "${SRCROOT}"
                go run "util/read_symbols.go" -obj-file-format elf -out "${TMPDIR}/symbols-linux-all.txt" "${HERE}"/.build/*-unknown-linux-gnu/debug/libCBigNumBoringSSL.a
            )
        fi

        # Now we concatenate all the symbols together and uniquify it. At this stage remove anything that
        # already has CBigNumBoringSSL in it, as those are namespaced by nature.
        cat "${TMPDIR}"/symbols-*.txt | sort | uniq | grep -v "CBigNumBoringSSL" > "${TMPDIR}/symbols.txt"

        # Use this as the input to the mangle.
        echo "GENERATE mangle prefix headers"
        (
            cd "${SRCROOT}"
            go run "util/make_prefix_headers.go" -out "${HERE}/${DSTROOT}/include/openssl" "${TMPDIR}/symbols.txt"
        )

        # Remove the product, as we no longer need it.
        $sed -i -e 's/MANGLE_START\*\//MANGLE_START/' -e 's/\/\*MANGLE_END/MANGLE_END/' "${HERE}/Package.swift"
    )

    # Now remove any weird symbols that got in and would emit warnings.
    $sed -i -e '/#define .*\..*/d' "${DSTROOT}"/include/openssl/boringssl_prefix_symbols*.h

    # Now edit the headers again to add the symbol mangling.
    echo "ADDING symbol mangling"
    perl -pi -e '$_ .= qq(\n#define BORINGSSL_PREFIX CBigNumBoringSSL\n) if /#define OPENSSL_HEADER_BASE_H/' "$DSTROOT/include/openssl/base.h"
    echo "ASSEMBLY"

    # shellcheck disable=SC2044
    for assembly_file in $(find "$DSTROOT" -name "*.S")
    do
        $sed -i '1 i #define BORINGSSL_PREFIX CBigNumBoringSSL' "$assembly_file"
    done
    namespace_inlines "$DSTROOT"
}

case "$(uname -s)" in
    Darwin)
        sed=gsed
        ;;
    *)
        # shellcheck disable=SC2209
        sed=sed
        ;;
esac

if ! hash ${sed} 2>/dev/null; then
    echo "You need sed \"${sed}\" to run this script ..."
    echo
    echo "On macOS: brew install gnu-sed"
    exit 43
fi

CLONE_LATEST=""
KEEP_TEMP_FOLDER=""
IOS_BUILD_INCLUDED=""
LINUX_BUILD_INCLUDED=""

while getopts 'ckil:' option
do
    case $option in
        c) CLONE_LATEST=1 ;;
        k) KEEP_TEMP_FOLDER=1 ;;
        i) IOS_BUILD_INCLUDED=1 ;;
        l) LINUX_BUILD_INCLUDED=1 ;;
    esac
done

echo "REMOVING any previously-vendored BoringSSL code"
rm -rf $DSTROOT/include
rm -rf $DSTROOT/ssl
rm -rf $DSTROOT/crypto
rm -rf $DSTROOT/gen
rm -rf $DSTROOT/third_party

if [ -n "$CLONE_LATEST" ]; then
    echo "CLONING boringssl"
    mkdir -p "$SRCROOT"
    git clone https://boringssl.googlesource.com/boringssl "$SRCROOT"
fi

cd "$SRCROOT"
git checkout .
BORINGSSL_REVISION=$(git rev-parse HEAD)
cd "$HERE"
echo "CLONED boringssl@${BORINGSSL_REVISION}"

echo "OBTAINING submodules"
(
    cd "$SRCROOT"
    git submodule update --init
)

echo "GENERATING assembly helpers"
(
    cd "$SRCROOT"
    cd ..
    mkdir -p "${SRCROOT}/crypto/third_party/sike/asm"
    python3 "${HERE}/scripts/build-asm.py"
)

PATTERNS=(
'include/openssl/aead.h'
'include/openssl/aes.h'
'include/openssl/arm_arch.h'
'include/openssl/asm_base.h'
'include/openssl/asn1.h'
'include/openssl/asn1t.h'
'include/openssl/base.h'
'include/openssl/bcm_public.h'
'include/openssl/bio.h'
'include/openssl/bn.h'
'include/openssl/buf.h'
'include/openssl/buffer.h'
'include/openssl/bytestring.h'
'include/openssl/chacha.h'
'include/openssl/cipher.h'
'include/openssl/cpu.h'
'include/openssl/crypto.h'
'include/openssl/ctrdrbg.h'
'include/openssl/ec.h'
'include/openssl/err.h'
'include/openssl/ex_data.h'
'include/openssl/is_boringssl.h'
'include/openssl/opensslconf.h'
'include/openssl/mem.h'
'include/openssl/nid.h'
'include/openssl/rand.h'
'include/openssl/sha.h'
'include/openssl/span.h'
'include/openssl/stack.h'
'include/openssl/service_indicator.h'
'include/openssl/posix_time.h'
'include/openssl/thread.h'
'include/openssl/type_check.h'
'include/openssl/target.h'
'crypto/*.h'
'crypto/*.cc'
'crypto/asn1/*.h'
'crypto/asn1/posix_time.cc'
'crypto/bio/bio.cc'
'crypto/bio/file.cc'
'crypto/bn/convert.cc'
'crypto/bytestring/*.h'
'crypto/bytestring/*.cc'
'crypto/err/*.h'
'crypto/err/*.cc'
'gen/crypto/*.S'
'gen/bcm/*.S'
'gen/crypto/err_data.cc'
'crypto/fipsmodule/*.h'
'crypto/fipsmodule/*.cc'
'crypto/fipsmodule/bn/*.h'
'crypto/fipsmodule/bn/*.cc.inc'
'crypto/fipsmodule/bn/*/*.cc.inc'
'crypto/fipsmodule/aes/*.h'
'crypto/fipsmodule/aes/*.cc.inc'
'crypto/fipsmodule/cipher/*.h'
'crypto/fipsmodule/cipher/cipher.cc.inc'
'crypto/fipsmodule/cipher/e_aes.cc.inc'
'crypto/fipsmodule/rand/*.h'
'crypto/fipsmodule/rand/*.cc.inc'
'crypto/fipsmodule/service_indicator/*.h'
'crypto/rand/*.h'
'crypto/rand/*.cc'
'crypto/stack/*.cc'
'third_party/fiat/*.h'
)

EXCLUDES=(
'*_test.*'
'test_*.*'
'test'
'example_*.cc'
)

echo "COPYING boringssl"
for pattern in "${PATTERNS[@]}"
do
  for i in $SRCROOT/$pattern; do
    path=${i#"$SRCROOT"}
    dest="$DSTROOT$path"
    dest_dir=$(dirname "$dest")
    mkdir -p "$dest_dir"
    cp "$SRCROOT/$path" "$dest"

    # https://boringssl-review.googlesource.com/c/boringssl/+/70849
    # TODO(crbug.com/362530616): When delocate is removed, build these files as separate compilation units again.
    # So for now we separate these files into compilation units.
    if [ "${dest: -7}" == ".cc.inc" ]; then
        mv -- "$dest" "${dest%.cc.inc}.cc"
    fi
  done
done

for exclude in "${EXCLUDES[@]}"
do
  echo "EXCLUDING $exclude"
  find $DSTROOT -d -name "$exclude" -exec rm -rf {} \;
done

#echo "REMOVING libssl"
#(
#    cd "$DSTROOT"
#    rm "include/openssl/dtls1.h" "include/openssl/ssl.h" "include/openssl/srtp.h" "include/openssl/ssl3.h" "include/openssl/tls1.h"
#    rm -rf "ssl"
#)
echo "REMOVING crypto/fipsmodule/bcm.cc"
rm -f $DSTROOT/crypto/fipsmodule/bcm.cc

echo "DISABLING assembly on x86 Windows"
(
    # x86 Windows builds require nasm for acceleration. SwiftPM can't do that right now,
    # so we disable the assembly.
    cd "$DSTROOT"
    gsed -i "/#define OPENSSL_HEADER_BASE_H/a#if defined(_WIN32) && (defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64) || defined(__x86) || defined(__i386) || defined(__i386__) || defined(_M_IX86))\n#define OPENSSL_NO_ASM\n#endif" "include/openssl/base.h"
)

mangle_symbols

echo "RENAMING header files"
(
    # We need to rearrange a coouple of things here, the end state will be:
    # - Headers from 'include/openssl/' will be moved up a level to 'include/'
    # - Their names will be prefixed with 'CBigNumBoringSSL_'
    # - The headers prefixed with 'boringssl_prefix_symbols' will also be prefixed with 'CBigNumBoringSSL_'
    # - Any include of another header in the 'include/' directory will use quotation marks instead of angle brackets

    # Let's move the headers up a level first.
    cd "$DSTROOT"
    mv include/openssl/* include/
    rmdir "include/openssl"

    # Now change the imports from "<openssl/X> to "<CBigNumBoringSSL_X>", apply the same prefix to the 'boringssl_prefix_symbols' headers.
    # shellcheck disable=SC2038
    find . -name "*.[ch]" -or -name "*.cc" -or -name "*.S" -or -name "*.c.inc" -or -name "*.cc.inc" | xargs $sed -i -e 's+include <openssl/\([[:alpha:]/]*/\)\{0,1\}+include <\1CBigNumBoringSSL_+' -e 's+include <boringssl_prefix_symbols+include <CBigNumBoringSSL_boringssl_prefix_symbols+' -e 's+include "openssl/\([[:alpha:]/]*/\)\{0,1\}+include "\1CBigNumBoringSSL_+'

    # Okay now we need to rename the headers adding the prefix "CBigNumBoringSSL_".
    pushd include
    while IFS= read -r -u3 -d $'\0' file; do
        dir=$(dirname "${file}")
        base=$(basename "${file}")
        mv "${file}" "${dir}/CBigNumBoringSSL_${base}"
    done 3< <(find . -name "*.h" -print0 | sort -rz)

    # Finally, make sure we refer to them by their prefixed names, and change any includes from angle brackets to quotation marks.
    # shellcheck disable=SC2038
    find . -name "*.h" | xargs $sed -i -e 's+include "\([[:alpha:]/]*/\)\{0,1\}+include "\1CBigNumBoringSSL_+' -e 's+include <\([[:alpha:]/]*/\)\{0,1\}CBigNumBoringSSL_\(.*\)>+include "\1CBigNumBoringSSL_\2"+'
    popd
)

# We need to avoid having the stack be executable. BoringSSL does this in its build system, but we can't.
echo "PROTECTING against executable stacks"
(
    cd "$DSTROOT"
    # shellcheck disable=SC2038
    find . -name "*.S" | xargs $sed -i '$ a #if defined(__linux__) && defined(__ELF__)\n.section .note.GNU-stack,"",%progbits\n#endif\n'
)

echo "PATCHING BoringSSL"
git apply "${HERE}/scripts/patch-1-inttypes.patch"

# We need BoringSSL to be modularised
echo "MODULARISING BoringSSL"
cat << EOF > "$DSTROOT/include/CBigNumBoringSSL.h"
#ifndef C_BIGNUM_BORINGSSL_H
#define C_BIGNUM_BORINGSSL_H

#include "CBigNumBoringSSL_aead.h"
#include "CBigNumBoringSSL_aes.h"
#include "CBigNumBoringSSL_arm_arch.h"
#include "CBigNumBoringSSL_asn1.h"
#include "CBigNumBoringSSL_bio.h"
#include "CBigNumBoringSSL_bn.h"
#include "CBigNumBoringSSL_boringssl_prefix_symbols_asm.h"
#include "CBigNumBoringSSL_bytestring.h"
#include "CBigNumBoringSSL_chacha.h"
#include "CBigNumBoringSSL_cipher.h"
#include "CBigNumBoringSSL_cpu.h"
#include "CBigNumBoringSSL_crypto.h"
#include "CBigNumBoringSSL_err.h"
#include "CBigNumBoringSSL_nid.h"
#include "CBigNumBoringSSL_rand.h"


#endif  // C_BIGNUM_BORINGSSL_H
EOF

#include "CBigNumBoringSSL_aes.h"
#include "CBigNumBoringSSL_bio.h"
#include "CBigNumBoringSSL_bn.h"
#include "CBigNumBoringSSL_cipher.h"
#include "CBigNumBoringSSL_cpu.h"
#include "CBigNumBoringSSL_crypto.h"
#include "CBigNumBoringSSL_bytestring.h"
#include "CBigNumBoringSSL_err.h"
#include "CBigNumBoringSSL_rand.h"

# modulemap is required by the cmake build
echo "CREATING modulemap"
cat << EOF > "$DSTROOT/include/module.modulemap"
module CBigNumBoringSSL {
    header "CBigNumBoringSSL.h"
    export *
}
EOF

echo "RECORDING BoringSSL revision"
$sed -i -e "s/BoringSSL Commit: [0-9a-f]\+/BoringSSL Commit: ${BORINGSSL_REVISION}/" "$HERE/Package.swift"
echo "This directory is derived from BoringSSL cloned from https://boringssl.googlesource.com/boringssl at revision ${BORINGSSL_REVISION}" > "$DSTROOT/hash.txt"

if [ -z "$KEEP_TEMP_FOLDER" ]; then
    echo "CLEANING temporary directory"
    rm -rf "${TMPDIR}"
fi
