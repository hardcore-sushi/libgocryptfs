#!/bin/bash

set -e

if [ -z ${ANDROID_NDK_HOME+x} ]; then
  echo "Error: \$ANDROID_NDK_HOME is not defined." >&2
  exit 1
else
  OPENSSL_PATH="openssl"
  NDK_BIN_PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
  declare -a ABIs=("x86_64" "x86" "arm64-v8a" "armeabi-v7a")

  invalid_abi() {
    echo "Invalid ABI: $1" >&2
    exit 1
  }

  compile_openssl(){
    if [ ! -d "./lib/$1" ]; then
      if [ "$1" = "x86_64" ]; then
        OPENSSL_ARCH="android-x86_64"
      elif [ "$1" = "x86" ]; then
        OPENSSL_ARCH="android-x86"
      elif [ "$1" = "arm64-v8a" ]; then
        OPENSSL_ARCH="android-arm64"
      elif [ "$1" = "armeabi-v7a" ]; then
        OPENSSL_ARCH="android-arm"
      else
        invalid_abi "$1"
      fi

      export CFLAGS=-D__ANDROID_API__=21
      export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$ANDROID_NDK_HOME/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH
      (
        cd "$OPENSSL_PATH"
        export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
        if [ -f "Makefile" ]; then
                make clean
        fi
        ./Configure $OPENSSL_ARCH -D__ANDROID_API__=21
        make -j "$(nproc --all)" build_libs
      )
      mkdir -p "./lib/$1" "./include/$1"
      cp "$OPENSSL_PATH/libcrypto.a" "$OPENSSL_PATH/libssl.a" "./lib/$1"
      cp -r "$OPENSSL_PATH"/include/* "./include/$1/"
    fi
  }

  compile_for_arch() {
    compile_openssl "$1"
    if [ "$1" = "x86_64" ]; then
      CFN="x86_64-linux-android21-clang"
    elif [ "$1" = "x86" ]; then
      export GOARCH=386
      CFN="i686-linux-android21-clang"
    elif [ "$1" = "arm64-v8a" ]; then
      CFN="aarch64-linux-android21-clang"
      export GOARCH=arm64
      export GOARM=7
    elif [ "$1" = "armeabi-v7a" ]; then
      CFN="armv7a-linux-androideabi21-clang"
      export GOARCH=arm
      export GOARM=7
    else
      invalid_abi "$1"
    fi

    export CC="$NDK_BIN_PATH/$CFN"
    export CXX="$NDK_BIN_PATH/$CFN++"
    export CGO_ENABLED=1
    export GOOS=android
    export CGO_CFLAGS="-I ${PWD}/include/$1"
    export CGO_LDFLAGS="-Wl,-soname=libgocryptfs.so -L${PWD}/lib/$1"
    go build -o "build/$1/libgocryptfs.so" -buildmode=c-shared
  }

  cd "$(dirname "$0")"
  if [ "$#" -eq 1 ]; then
    compile_for_arch "$1"
  else
    for abi in "${ABIs[@]}"; do
      echo "Compiling for $abi..."
      compile_for_arch "$abi"
    done
  fi
fi
