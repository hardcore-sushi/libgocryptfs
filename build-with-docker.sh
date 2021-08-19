set -xe
if [ ! -f openssl-1.1.1k.tar.gz ]; then
    wget https://www.openssl.org/source/openssl-1.1.1k.tar.gz
fi
docker build . -t libgocryptfs
docker create --name libgocryptfs-instance libgocryptfs
docker cp libgocryptfs-instance:/work/build .
docker cp libgocryptfs-instance:/build-results.tar .
docker container rm libgocryptfs-instance
