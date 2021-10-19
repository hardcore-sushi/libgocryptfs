package syscallcompat

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// PATH_MAX is the maximum allowed path length on Linux.
// It is not defined on Darwin, so we use the Linux value.
const PATH_MAX = 4096

// Readlinkat is a convenience wrapper around unix.Readlinkat() that takes
// care of buffer sizing. Implemented like os.Readlink().
func Readlinkat(dirfd int, path string) (string, error) {
	// Allocate the buffer exponentially like os.Readlink does.
	for bufsz := 128; ; bufsz *= 2 {
		buf := make([]byte, bufsz)
		n, err := unix.Readlinkat(dirfd, path, buf)
		if err != nil {
			return "", err
		}
		if n < bufsz {
			return string(buf[0:n]), nil
		}
	}
}

// Openat wraps the Openat syscall.
// Retries on EINTR.
func Openat(dirfd int, path string, flags int, mode uint32) (fd int, err error) {
	if flags&syscall.O_CREAT == 0 {
		// If O_CREAT is not used, we should use O_NOFOLLOW
		if flags&syscall.O_NOFOLLOW == 0 {
			flags |= syscall.O_NOFOLLOW
		}
	}
	fd, err = retryEINTR2(func() (int, error) {
		return unix.Openat(dirfd, path, flags, mode)
	})
	return fd, err
}

// Fstatat syscall.
// Retries on EINTR.
func Fstatat(dirfd int, path string, stat *unix.Stat_t, flags int) (err error) {
	// Why would we ever want to call this without AT_SYMLINK_NOFOLLOW?
	if flags&unix.AT_SYMLINK_NOFOLLOW == 0 {
		flags |= unix.AT_SYMLINK_NOFOLLOW
	}
	err = retryEINTR(func() error {
		return unix.Fstatat(dirfd, path, stat, flags)
	})
	return err
}

// Fstatat2 is a more convenient version of Fstatat. It allocates a Stat_t
// for you and also handles the Unix2syscall conversion.
// Retries on EINTR.
func Fstatat2(dirfd int, path string, flags int) (*syscall.Stat_t, error) {
	var stUnix unix.Stat_t
	err := Fstatat(dirfd, path, &stUnix, flags)
	if err != nil {
		return nil, err
	}
	st := Unix2syscall(stUnix)
	return &st, nil
}

const XATTR_SIZE_MAX = 65536

// Make the buffer 1kB bigger so we can detect overflows. Unfortunately,
// slices larger than 64kB are always allocated on the heap.
const XATTR_BUFSZ = XATTR_SIZE_MAX + 1024

// We try with a small buffer first - this one can be allocated on the stack.
const XATTR_BUFSZ_SMALL = 500
