FROM smithmicro/android-build:28-ndk21

USER root
RUN apt-get update \
    && apt-get install --no-install-recommends -y golang make gcc libcrypto++-dev libssl-dev pkg-config \
    && groupadd builder && useradd -m -g builder builder

USER builder
RUN go get golang.org/x/sys/unix golang.org/x/sys/cpu golang.org/x/crypto/hkdf github.com/jacobsa/crypto/siv github.com/rfjakob/eme
WORKDIR /work
CMD ["/bin/bash", "/work/build.sh"]