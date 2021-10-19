@ECHO OFF
ECHO.
ECHO Before we continue, please untar OpenSSL source code to libgocryptfs/openssl/
ECHO.
PAUSE
docker build . -t libgocryptfs
docker container rm libgocryptfs-instance
docker run --name libgocryptfs-instance --env FORCE_INSTALL_GO_DEPS=1 --env OPENSSL_PATH=./openssl --mount type=bind,src=%~dp0,dst=/work libgocryptfs
PAUSE