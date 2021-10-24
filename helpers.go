package main

import (
	"path/filepath"
	"strings"
	"syscall"

	"libgocryptfs/v2/internal/configfile"
	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/syscallcompat"
)

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

func (volume *Volume) openBackingDir(relPath string) (dirfd int, cName string, err error) {
	dirRelPath := nametransform.Dir(relPath)
	// With PlaintextNames, we don't need to read DirIVs. Easy.
	if volume.plainTextNames {
		dirfd, err = syscallcompat.OpenDirNofollow(volume.rootCipherDir, dirRelPath)
		if err != nil {
			return -1, "", err
		}
		// If relPath is empty, cName is ".".
		cName = filepath.Base(relPath)
		return dirfd, cName, nil
	}
	// Open cipherdir (following symlinks)
	dirfd, err = syscallcompat.Open(volume.rootCipherDir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		return -1, "", err
	}
	// If relPath is empty, cName is ".".
	if relPath == "" {
		return dirfd, ".", nil
	}
	// Walk the directory tree
	parts := strings.Split(relPath, "/")
	for i, name := range parts {
		iv, err := volume.nameTransform.ReadDirIVAt(dirfd)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", err
		}
		cName, err = volume.nameTransform.EncryptAndHashName(name, iv)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", err
		}
		// Last part? We are done.
		if i == len(parts)-1 {
			break
		}
		// Not the last part? Descend into next directory.
		dirfd2, err := syscallcompat.Openat(dirfd, cName, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		syscall.Close(dirfd)
		if err != nil {
			return -1, "", err
		}
		dirfd = dirfd2
	}
	return dirfd, cName, nil
}

func (volume *Volume) prepareAtSyscall(path string) (dirfd int, cName string, err error) {
	// root node itself is special
	if path == "" {
		return volume.openBackingDir(path)
	}

	// Cache lookup
	// TODO make it work for plaintextnames as well?
	if !volume.plainTextNames {
		directory, ok := volume.dirCache[path]
		if ok {
			if directory.fd > 0 {
				cName, err := volume.nameTransform.EncryptAndHashName(filepath.Base(path), directory.iv)
				if err != nil {
					return -1, "", err
				}
				dirfd, err = syscall.Dup(directory.fd)
				if err != nil {
					return -1, "", err
				}
				return dirfd, cName, nil
			}
		}
	}

	// Slowpath
	if volume.isFiltered(path) {
		return -1, "", syscall.EPERM
	}
	dirfd, cName, err = volume.openBackingDir(path)
	if err != nil {
		return -1, "", err
	}

	// Cache store
	if !volume.plainTextNames {
		// TODO: openBackingDir already calls ReadDirIVAt(). Avoid duplicate work?
		iv, err := volume.nameTransform.ReadDirIVAt(dirfd)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", err
		}
		dirfdDup, err := syscall.Dup(dirfd)
		if err == nil {
			var pathCopy strings.Builder
			pathCopy.WriteString(path)
			volume.dirCache[pathCopy.String()] = Directory{dirfdDup, iv}
		}
	}
	return
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
		target := volume.readlink(dirfd, cName)
		size = uint64(len(target))
	}
	return size
}
