@ECHO OFF
ECHO.
ECHO Before we continue, please download https://www.openssl.org/source/openssl-1.1.1k.tar.gz to libgocryptfs folder
ECHO.
PAUSE
@ECHO OFF
docker build . -t libgocryptfs
docker create --name libgocryptfs-instance libgocryptfs
docker cp libgocryptfs-instance:/work/build .
docker cp libgocryptfs-instance:/build-results.tar .
docker container rm libgocryptfs-instance
