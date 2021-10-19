set -e
if [ ! -f openssl.tar ]; then
    echo "Before we continue, please untar OpenSSL source code to libgocryptfs/openssl/"
    exit 1
fi
docker build . -t libgocryptfs
docker container rm libgocryptfs-instance
docker run --name libgocryptfs-instance --env FORCE_INSTALL_GO_DEPS=1 --env OPENSSL_PATH=./openssl --mount type=bind,src="$(pwd)",dst=/work libgocryptfs