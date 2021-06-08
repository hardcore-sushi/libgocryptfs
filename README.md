libgocryptfs is a re-desing of the original [gocryptfs](https://github.com/rfjakob/gocryptfs) code to work as a library. Volumes are not mounted with [FUSE](https://www.kernel.org/doc/html/latest/filesystems/fuse.html) but rather opened in memory and accessed through API calls. What the purpose ?
- Allow the use of gocryptfs in embedded devices where FUSE is not available (such as Android)
- Reduce attack surface by restricting volumes access to only one process rather than one user

## Warning !
The only goal of this library is to be integrated in [DroidFS](https://forge.chapril.org/hardcoresushi/DroidFS). It's not actually ready for other usages. libgocryptfs doesn't implement all features provided by gocryptfs like symbolic links creation, thread-safety, reverse volume creation... Use it at your own risk !