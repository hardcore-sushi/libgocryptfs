FROM smithmicro/android-build:28-ndk21

USER root
RUN apt-get update \
    && apt-get install --no-install-recommends -y golang make gcc libcrypto++-dev libssl-dev pkg-config \
    && groupadd builder && useradd -g builder builder \
    && mkdir -p /home/builder && chown -R builder:builder /home/builder

USER builder
WORKDIR /work
CMD ["/bin/bash", "/work/build.sh"]