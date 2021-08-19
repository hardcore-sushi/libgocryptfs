FROM smithmicro/android-build:28-ndk21

RUN apt-get update && apt-get install --no-install-recommends -y golang make gcc libcrypto++-dev libssl-dev pkg-config

COPY . /work
RUN cd /work; go get golang.org/x/sys/unix golang.org/x/sys/cpu golang.org/x/crypto/hkdf github.com/jacobsa/crypto/siv github.com/rfjakob/eme \
    rm -rf /work/lib/*; tar xzf openssl-1.1.1k.tar.gz; \
    env ANDROID_NDK_HOME="$(echo /opt/android-sdk/ndk/*)" OPENSSL_PATH=./openssl-1.1.1k ./build.sh; \
    cd /work/build; tar cvf /build-results.tar .
