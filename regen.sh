#!/usr/bin/env sh

set -eu

LLVM_DIR=~/local/llvm-build
LIBPCAP_DIR=~/local/libpcap-libpcap-1.8.1

export C_INCLUDE_PATH=$LLVM_DIR/lib/clang/6.0.0/include
export LD_LIBRARY_PATH=$LLVM_DIR/lib

bindgen $LIBPCAP_DIR/pcap/pcap.h --blacklist-type FILE --no-layout-tests --no-prepend-enum-name -o src/pcap.rs -- -I$LIBPCAP_DIR
