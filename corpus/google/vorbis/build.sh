#!/bin/bash
# Copyright 2017 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");

readonly INSTALL_DIR="$PWD/INSTALL"

get_git_revision() {
  GIT_REPO="$1"
  GIT_REVISION="$2"
  TO_DIR="$3"
  [ ! -e $TO_DIR ] && git clone $GIT_REPO $TO_DIR && (cd $TO_DIR && git reset --hard $GIT_REVISION)
}

build_ogg() {
  rm -rf BUILD/ogg
  mkdir -p BUILD/ogg $INSTALL_DIR
  cp -r SRC/ogg/* BUILD/ogg/
  (cd BUILD/ogg && ./autogen.sh && ./configure \
    --prefix="$INSTALL_DIR" \
    --enable-static \
    --disable-shared \
    --disable-crc \
    && make clean && make -j $JOBS && make install)
}

build_vorbis() {
  rm -rf BUILD/vorbis
  mkdir -p BUILD/vorbis $INSTALL_DIR
  cp -r SRC/vorbis/* BUILD/vorbis/
  (cd BUILD/vorbis && ./autogen.sh && ./configure \
    --prefix="$INSTALL_DIR" \
    --enable-static \
    --disable-shared \
    && make clean && make -j $JOBS && make install)
}

get_git_revision https://github.com/xiph/ogg.git \
  c8391c2b267a7faf9a09df66b1f7d324e9eb7766 SRC/ogg
get_git_revision https://github.com/xiph/vorbis.git \
  c1c2831fc7306d5fbd7bc800324efd12b28d327f SRC/vorbis

build_ogg
build_vorbis

if [[ $CXX == "" ]]; then
  CXX="g++"
fi

$CXX $CXXFLAGS decode_fuzzer.cc \
  -o decode_fuzzer.exe -L"$INSTALL_DIR/lib" -I"$INSTALL_DIR/include" \
  -lvorbisfile  -lvorbis -logg
