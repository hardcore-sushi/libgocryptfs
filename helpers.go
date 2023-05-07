package main

import (
	"path/filepath"
	"syscall"

	"libgocryptfs/v2/internal/configfile"
	"libgocryptfs/v2/internal/syscallcompat"
)

func getParentPath(path string) string {
	parent := filepath.Dir(path)
	if parent == "." {
		return ""
	}
	return parent
}

// isFiltered - check if plaintext "path" should be forbidden
//
// Prevents name clashes with internal files when file names are not encrypted
func (volume *Volume) isFiltered(path string) bool {
	if !volume.plainTextNames {
		return false
	}
	// gocryptfs.conf in the root directory is forbidden
	if path == configfile.ConfDefaultName {
		return true
	}
	// Note: gocryptfs.diriv is NOT forbidden because diriv and plaintextnames
	// are exclusive
	return false
}

func (volume *Volume) prepareAtSyscall(path string) (dirfd int, cName string, err error) {
	if path == "/" {
		return volume.prepareAtSyscallMyself(path)
	}

	if volume.isFiltered(path) {
		return -1, "", nil
	}

	var encryptName func(int, string, []byte) (string, error)
	if !volume.plainTextNames {
		encryptName = func(dirfd int, child string, iv []byte) (cName string, err error) {
			// Badname allowed, try to determine filenames
			if volume.nameTransform.HaveBadnamePatterns() {
				return volume.nameTransform.EncryptAndHashBadName(child, iv, dirfd)
			}
			return volume.nameTransform.EncryptAndHashName(child, iv)
		}
	}

	child := filepath.Base(path)
	parentPath := getParentPath(path)

	// Cache lookup
	var iv []byte
	dirfd, iv = volume.dirCache.Lookup(parentPath)
	if dirfd > 0 {
		if volume.plainTextNames {
			return dirfd, child, nil
		}
		var err error
		cName, err = encryptName(dirfd, child, iv)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", err
		}
		return dirfd, cName, nil
	}

	// Slowpath: Open ourselves & read diriv
	parentDirfd, myCName, err := volume.prepareAtSyscallMyself(parentPath)
	if err != nil {
		return
	}
	defer syscall.Close(parentDirfd)

	dirfd, err = syscallcompat.Openat(parentDirfd, myCName, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		return -1, "", err
	}

	// Cache store
	if !volume.plainTextNames {
		var err error
		iv, err = volume.nameTransform.ReadDirIVAt(dirfd)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", err
		}
	}
	volume.dirCache.Store(parentPath, dirfd, iv)

	if volume.plainTextNames {
		return dirfd, child, nil
	}

	cName, err = encryptName(dirfd, child, iv)
	if err != nil {
		syscall.Close(dirfd)
		return -1, "", err
	}

	return
}

func (volume *Volume) prepareAtSyscallMyself(path string) (dirfd int, cName string, err error) {
	dirfd = -1

	// Handle root node
	if path == "/" {
		var err error
		// Open cipherdir (following symlinks)
		dirfd, err = syscallcompat.Open(volume.rootCipherDir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err != nil {
			return -1, "", err
		}
		return dirfd, ".", nil
	}

	// Otherwise convert to prepareAtSyscall of parent node
	return volume.prepareAtSyscall(path)
}

// decryptSymlinkTarget: "cData64" is base64-decoded and decrypted
// like file contents (GCM).
// The empty string decrypts to the empty string.
//
// This function does not do any I/O and is hence symlink-safe.
func (volume *Volume) decryptSymlinkTarget(cData64 string) (string, error) {
	if cData64 == "" {
		return "", nil
	}
	cData, err := volume.nameTransform.B64DecodeString(cData64)
	if err != nil {
		return "", err
	}
	data, err := volume.contentEnc.DecryptBlock([]byte(cData), 0, nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// readlink reads and decrypts a symlink. Used by Readlink, Getattr, Lookup.
func (volume *Volume) readlink(dirfd int, cName string) []byte {
	cTarget, err := syscallcompat.Readlinkat(dirfd, cName)
	if err != nil {
		return nil
	}
	if volume.plainTextNames {
		return []byte(cTarget)
	}
	// Symlinks are encrypted like file contents (GCM) and base64-encoded
	target, err := volume.decryptSymlinkTarget(cTarget)
	if err != nil {
		return nil
	}
	return []byte(target)
}

func isRegular(mode uint32) bool { return (mode & syscall.S_IFMT) == syscall.S_IFREG }

func isSymlink(mode uint32) bool { return (mode & syscall.S_IFMT) == syscall.S_IFLNK }

// translateSize translates the ciphertext size in `out` into plaintext size.
// Handles regular files & symlinks (and finds out what is what by looking at
// `out.Mode`).
func (volume *Volume) translateSize(dirfd int, cName string, st *syscall.Stat_t) uint64 {
	size := uint64(st.Size)
	if isRegular(st.Mode) {
		size = volume.contentEnc.CipherSizeToPlainSize(uint64(st.Size))
	} else if isSymlink(st.Mode) {
		// read and decrypt target
		target := volume.readlink(dirfd, cName)
		size = uint64(len(target))
	}
	return size
}
