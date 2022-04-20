package main

import (
	"C"
	"syscall"
	"golang.org/x/sys/unix"

	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/syscallcompat"
)

//export gcf_get_attrs
func gcf_get_attrs(sessionID int, relPath string) (uint64, int64, bool) {
	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return 0, 0, false
	}
	volume := value.(*Volume)
	dirfd, cName, err := volume.prepareAtSyscall(relPath)
	if err != nil {
		return 0, 0, false
	}
	defer syscall.Close(dirfd)

	st, err := syscallcompat.Fstatat2(dirfd, cName, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return 0, 0, false
	}

	// Translate ciphertext size to plaintext size
	size := volume.translateSize(dirfd, cName, st)

	return size, int64(st.Mtim.Sec), true
}

// libgocryptfs: using Renameat instead of Renameat2 to support older kernels
//export gcf_rename
func gcf_rename(sessionID int, oldPath string, newPath string) bool {
	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return false
	}
	volume := value.(*Volume)
	dirfd, cName, err := volume.prepareAtSyscall(oldPath)
	if err != nil {
		return false
	}
	defer syscall.Close(dirfd)

	dirfd2, cName2, err := volume.prepareAtSyscall(newPath)
	if err != nil {
		return false
	}
	defer syscall.Close(dirfd2)

	// Easy case.
	if volume.plainTextNames {
		return errToBool(syscallcompat.Renameat(dirfd, cName, dirfd2, cName2))
	}
	// Long destination file name: create .name file
	nameFileAlreadyThere := false
	if nametransform.IsLongContent(cName2) {
		err = volume.nameTransform.WriteLongNameAt(dirfd2, cName2, newPath)
		// Failure to write the .name file is expected when the target path already
		// exists. Since hashes are pretty unique, there is no need to modify the
		// .name file in this case, and we ignore the error.
		if err == syscall.EEXIST {
			nameFileAlreadyThere = true
		} else if err != nil {
			return false
		}
	}
	// Actual rename
	err = syscallcompat.Renameat(dirfd, cName, dirfd2, cName2)
	if err == syscall.ENOTEMPTY || err == syscall.EEXIST {
		// If an empty directory is overwritten we will always get an error as
		// the "empty" directory will still contain gocryptfs.diriv.
		// Interestingly, ext4 returns ENOTEMPTY while xfs returns EEXIST.
		// We handle that by trying to fs.Rmdir() the target directory and trying
		// again.
		if gcf_rmdir(sessionID, newPath) {
			err = syscallcompat.Renameat(dirfd, cName, dirfd2, cName2)
		}
	}
	if err != nil {
		if nametransform.IsLongContent(cName2) && !nameFileAlreadyThere {
			// Roll back .name creation unless the .name file was already there
			nametransform.DeleteLongNameAt(dirfd2, cName2)
		}
		return false
	}
	if nametransform.IsLongContent(cName) {
		nametransform.DeleteLongNameAt(dirfd, cName)
	}
	return true
}
