package main

import (
	"C"
	"bytes"
	"io"
	"math"
	"os"
	"syscall"

	"libgocryptfs/v2/internal/contentenc"
	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/syscallcompat"
)

// mangleOpenFlags is used by Create() and Open() to convert the open flags the user
// wants to the flags we internally use to open the backing file.
// The returned flags always contain O_NOFOLLOW.
func mangleOpenFlags(flags uint32) (newFlags int) {
	newFlags = int(flags)
	// Convert WRONLY to RDWR. We always need read access to do read-modify-write cycles.
	if (newFlags & syscall.O_ACCMODE) == syscall.O_WRONLY {
		newFlags = newFlags ^ os.O_WRONLY | os.O_RDWR
	}
	// We also cannot open the file in append mode, we need to seek back for RMW
	newFlags = newFlags &^ os.O_APPEND
	// O_DIRECT accesses must be aligned in both offset and length. Due to our
	// crypto header, alignment will be off, even if userspace makes aligned
	// accesses. Running xfstests generic/013 on ext4 used to trigger lots of
	// EINVAL errors due to missing alignment. Just fall back to buffered IO.
	newFlags = newFlags &^ syscallcompat.O_DIRECT
	// Create and Open are two separate FUSE operations, so O_CREAT should not
	// be part of the open flags.
	newFlags = newFlags &^ syscall.O_CREAT
	// We always want O_NOFOLLOW to be safe against symlink races
	newFlags |= syscall.O_NOFOLLOW
	return newFlags
}

func (volume *Volume) registerFileHandle(fd int, cName, path string) int {
	volume.handlesLock.Lock()
	c := 0
	for {
		_, ok := volume.fileHandles[c]
		if !ok {
			break
		}
		c++
	}
	volume.fileHandles[c] = &File {
		fd: os.NewFile(uintptr(fd), cName),
		path: string([]byte(path[:])),
	}
	volume.handlesLock.Unlock()
	return c
}

// readFileID loads the file header from disk and extracts the file ID.
// Returns io.EOF if the file is empty.
func readFileID(fd *os.File) ([]byte, error) {
	// We read +1 byte to determine if the file has actual content
	// and not only the header. A header-only file will be considered empty.
	// This makes File ID poisoning more difficult.
	readLen := contentenc.HeaderLen + 1
	buf := make([]byte, readLen)
	_, err := fd.ReadAt(buf, 0)
	if err != nil {
		return nil, err
	}
	buf = buf[:contentenc.HeaderLen]
	h, err := contentenc.ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	return h.ID, nil
}

// createHeader creates a new random header and writes it to disk.
// Returns the new file ID.
// The caller must hold fileIDLock.Lock().
func createHeader(fd *os.File) (fileID []byte, err error) {
	h := contentenc.RandomHeader()
	buf := h.Pack()
	// Prevent partially written (=corrupt) header by preallocating the space beforehand
	err = syscallcompat.EnospcPrealloc(int(fd.Fd()), 0, contentenc.HeaderLen)
	if err != nil {
		return nil, err
	}
	// Actually write header
	_, err = fd.WriteAt(buf, 0)
	if err != nil {
		return nil, err
	}
	return h.ID, err
}

// doRead - read "length" plaintext bytes from plaintext offset "off" and append
// to "dst".
// Arguments "length" and "off" do not have to be block-aligned.
//
// doRead reads the corresponding ciphertext blocks from disk, decrypts them and
// returns the requested part of the plaintext.
//
// Called by Read() for normal reading,
// by Write() and Truncate() via doWrite() for Read-Modify-Write.
func (volume *Volume) doRead(f *File, dst []byte, off uint64, length uint64) ([]byte, bool) {
	fd := f.fd
	// Get the file ID, either from the open file table, or from disk.
	var fileID []byte
	if f.ID != nil {
		// Use the cached value in the file table
		fileID = f.ID
	} else {
		// Not cached, we have to read it from disk.
		var err error
		fileID, err = readFileID(fd)
		if err != nil {
			return nil, false
		}
		// Save into the file table
		f.ID = fileID
	}
	// Read the backing ciphertext in one go
	blocks := volume.contentEnc.ExplodePlainRange(off, length)
	alignedOffset, alignedLength := blocks[0].JointCiphertextRange(blocks)
	// f.fd.ReadAt takes an int64!
	if alignedOffset > math.MaxInt64 {
		return nil, false
	}
	skip := blocks[0].Skip

	ciphertext := volume.contentEnc.CReqPool.Get()
	ciphertext = ciphertext[:int(alignedLength)]
	n, err := fd.ReadAt(ciphertext, int64(alignedOffset))
	if err != nil && err != io.EOF {
		return nil, false
	}
	// The ReadAt came back empty. We can skip all the decryption and return early.
	if n == 0 {
		volume.contentEnc.CReqPool.Put(ciphertext)
		return dst, true
	}
	// Truncate ciphertext buffer down to actually read bytes
	ciphertext = ciphertext[0:n]

	firstBlockNo := blocks[0].BlockNo

	// Decrypt it
	plaintext, err := volume.contentEnc.DecryptBlocks(ciphertext, firstBlockNo, fileID)
	volume.contentEnc.CReqPool.Put(ciphertext)
	if err != nil {
		return nil, false
	}

	// Crop down to the relevant part
	var out []byte
	lenHave := len(plaintext)
	lenWant := int(skip + length)
	if lenHave > lenWant {
		out = plaintext[skip:lenWant]
	} else if lenHave > int(skip) {
		out = plaintext[skip:lenHave]
	}
	// else: out stays empty, file was smaller than the requested offset

	out = append(dst, out...)
	volume.contentEnc.PReqPool.Put(plaintext)

	return out, true
}

// doWrite - encrypt "data" and write it to plaintext offset "off"
//
// Arguments do not have to be block-aligned, read-modify-write is
// performed internally as necessary
//
// Called by Write() for normal writing,
// and by Truncate() to rewrite the last file block.
//
// Empty writes do nothing and are allowed.
func (volume *Volume) doWrite(handleID int, data []byte, off uint64) (uint32, bool) {
	volume.handlesLock.RLock()
	f := volume.fileHandles[handleID]
	volume.handlesLock.RUnlock()
	fd := f.fd
	fileWasEmpty := false
	var fileID []byte
	if f.ID != nil {
		fileID = f.ID
	} else {
		// If the file ID is not cached, read it from disk
		var err error
		fileID, err = readFileID(fd)
		// Write a new file header if the file is empty
		if err == io.EOF {
			fileID, err = createHeader(fd)
			fileWasEmpty = true
		}
		if err != nil {
			return 0, false
		}
		f.ID = fileID
	}
	// Handle payload data
	dataBuf := bytes.NewBuffer(data)
	blocks := volume.contentEnc.ExplodePlainRange(off, uint64(len(data)))
	toEncrypt := make([][]byte, len(blocks))
	for i, b := range blocks {
		blockData := dataBuf.Next(int(b.Length))
		// Incomplete block -> Read-Modify-Write
		if b.IsPartial() {
			// Read
			oldData, success := volume.doRead(f, nil, b.BlockPlainOff(), volume.contentEnc.PlainBS())
			if !success {
				return 0, false
			}
			// Modify
			blockData = volume.contentEnc.MergeBlocks(oldData, blockData, int(b.Skip))
		}
		// Write into the to-encrypt list
		toEncrypt[i] = blockData
	}
	// Encrypt all blocks
	ciphertext := volume.contentEnc.EncryptBlocks(toEncrypt, blocks[0].BlockNo, fileID)
	// Preallocate so we cannot run out of space in the middle of the write.
	// This prevents partially written (=corrupt) blocks.
	var err error
	cOff := blocks[0].BlockCipherOff()
	// f.fd.WriteAt & syscallcompat.EnospcPrealloc take int64 offsets!
	if cOff > math.MaxInt64 {
		return 0, false
	}
	err = syscallcompat.EnospcPrealloc(int(fd.Fd()), int64(cOff), int64(len(ciphertext)))
	if err != nil {
		if fileWasEmpty {
			// Kill the file header again
			syscall.Ftruncate(int(fd.Fd()), 0)
			gcf_close_file(volume.volumeID, handleID)
		}
		return 0, false
	}
	// Write
	_, err = f.fd.WriteAt(ciphertext, int64(cOff))
	// Return memory to CReqPool
	volume.contentEnc.CReqPool.Put(ciphertext)
	if err != nil {
		return 0, false
	}
	return uint32(len(data)), true
}

// Zero-pad the file of size plainSize to the next block boundary. This is a no-op
// if the file is already block-aligned.
func (volume *Volume) zeroPad(handleID int, plainSize uint64) bool {
	lastBlockLen := plainSize % volume.contentEnc.PlainBS()
	if lastBlockLen == 0 {
		// Already block-aligned
		return true
	}
	missing := volume.contentEnc.PlainBS() - lastBlockLen
	pad := make([]byte, missing)
	_, success := volume.doWrite(handleID, pad, plainSize)
	return success
}

// truncateGrowFile extends a file using seeking or ftruncate performing RMW on
// the first and last block as necessary. New blocks in the middle become
// file holes unless they have been fallocate()'d beforehand.
func (volume *Volume) truncateGrowFile(handleID int, oldPlainSz uint64, newPlainSz uint64) bool {
	if newPlainSz <= oldPlainSz {
		return false
	}
	newEOFOffset := newPlainSz - 1
	if oldPlainSz > 0 {
		n1 := volume.contentEnc.PlainOffToBlockNo(oldPlainSz - 1)
		n2 := volume.contentEnc.PlainOffToBlockNo(newEOFOffset)
		// The file is grown within one block, no need to pad anything.
		// Write a single zero to the last byte and let doWrite figure out the RMW.
		if n1 == n2 {
			buf := make([]byte, 1)
			_, success := volume.doWrite(handleID, buf, newEOFOffset)
			return success
		}
	}
	// The truncate creates at least one new block.
	//
	// Make sure the old last block is padded to the block boundary. This call
	// is a no-op if it is already block-aligned.
	success := volume.zeroPad(handleID, oldPlainSz)
	if !success {
		return false
	}
	// The new size is block-aligned. In this case we can do everything ourselves
	// and avoid the call to doWrite.
	if newPlainSz%volume.contentEnc.PlainBS() == 0 {
		volume.handlesLock.RLock()
		f := volume.fileHandles[handleID]
		volume.handlesLock.RUnlock()
		// The file was empty, so it did not have a header. Create one.
		if oldPlainSz == 0 {
			id, err := createHeader(f.fd)
			if err != nil {
				return false
			}
			f.ID = id
		}
		cSz := int64(volume.contentEnc.PlainSizeToCipherSize(newPlainSz))
		err := syscall.Ftruncate(int(f.fd.Fd()), cSz)
		return errToBool(err)
	}
	// The new size is NOT aligned, so we need to write a partial block.
	// Write a single zero to the last byte and let doWrite figure it out.
	buf := make([]byte, 1)
	_, success = volume.doWrite(handleID, buf, newEOFOffset)
	return success
}

func (volume *Volume) truncate(handleID int, newSize uint64) bool {
	volume.handlesLock.RLock()
	f := volume.fileHandles[handleID]
	volume.handlesLock.RUnlock()
	fileFD := int(f.fd.Fd())
	var err error
	// Common case first: Truncate to zero
	if newSize == 0 {
		err = syscall.Ftruncate(fileFD, 0)
		return err == nil
	}
	// We need the old file size to determine if we are growing or shrinking
	// the file
	oldSize, _, success := gcf_get_attrs(volume.volumeID, f.path)
	if !success {
		return false
	}

	// File size stays the same - nothing to do
	if newSize == oldSize {
		return true
	}
	// File grows
	if newSize > oldSize {
		return volume.truncateGrowFile(handleID, oldSize, newSize)
	}

	// File shrinks
	blockNo := volume.contentEnc.PlainOffToBlockNo(newSize)
	cipherOff := volume.contentEnc.BlockNoToCipherOff(blockNo)
	plainOff := volume.contentEnc.BlockNoToPlainOff(blockNo)
	lastBlockLen := newSize - plainOff
	var data []byte
	if lastBlockLen > 0 {
		data, success = volume.doRead(f, nil, plainOff, lastBlockLen)
		if !success {
			return false
		}
	}
	// Truncate down to the last complete block
	err = syscall.Ftruncate(fileFD, int64(cipherOff))
	if err != nil {
		return false
	}
	// Append partial block
	if lastBlockLen > 0 {
		_, success := volume.doWrite(handleID, data, plainOff)
		return success
	}
	return true
}

//export gcf_open_read_mode
func gcf_open_read_mode(sessionID int, path string) int {
	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return -1
	}
	volume := value.(*Volume)
	dirfd, cName, err := volume.prepareAtSyscallMyself(path)
	if err != nil {
		return -1
	}
	defer syscall.Close(dirfd)

	// Open backing file
	fd, err := syscallcompat.Openat(dirfd, cName, mangleOpenFlags(0), 0)
	if err != nil {
		return -1
	}
	return volume.registerFileHandle(fd, cName, path)
}

//export gcf_open_write_mode
func gcf_open_write_mode(sessionID int, path string, mode uint32) int {
	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return -1
	}
	volume := value.(*Volume)
	dirfd, cName, err := volume.prepareAtSyscall(path)
	if err != nil {
		return -1
	}
	defer syscall.Close(dirfd)

	fd := -1
	newFlags := mangleOpenFlags(syscall.O_RDWR)
	// Handle long file name
	if !volume.plainTextNames && nametransform.IsLongContent(cName) {
		// Create ".name"
		err = volume.nameTransform.WriteLongNameAt(dirfd, cName, path)
		if err != nil {
			return -1
		}
		// Create content
		fd, err = syscallcompat.Openat(dirfd, cName, newFlags|syscall.O_CREAT, mode)
		if err != nil {
			nametransform.DeleteLongNameAt(dirfd, cName)
		}
	} else {
		// Create content, normal (short) file name
		fd, err = syscallcompat.Openat(dirfd, cName, newFlags|syscall.O_CREAT, mode)
	}
	if err != nil {
		return -1
	}
	return volume.registerFileHandle(fd, cName, path)
}

//export gcf_truncate
func gcf_truncate(sessionID int, handleID int, offset uint64) bool {
	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return false
	}
	volume := value.(*Volume)
	return volume.truncate(handleID, offset)
}

//export gcf_read_file
func gcf_read_file(sessionID, handleID int, offset uint64, dst_buff []byte) uint32 {
	length := len(dst_buff)
	if length > contentenc.MAX_KERNEL_WRITE {
		// This would crash us due to our fixed-size buffer pool
		return 0
	}

	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return 0
	}
	volume := value.(*Volume)

	volume.handlesLock.RLock()
	f := volume.fileHandles[handleID]
	volume.handlesLock.RUnlock()
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	f.contentLock.RLock()
	defer f.contentLock.RUnlock()
	out, success := volume.doRead(f, dst_buff[:0], offset, uint64(length))
	if !success {
		return 0
	} else {
		return uint32(len(out))
	}
}

//export gcf_write_file
func gcf_write_file(sessionID, handleID int, offset uint64, data []byte) uint32 {
	length := len(data)
	if length > contentenc.MAX_KERNEL_WRITE {
		// This would crash us due to our fixed-size buffer pool
		return 0
	}

	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return 0
	}
	volume := value.(*Volume)

	volume.handlesLock.RLock()
	f := volume.fileHandles[handleID]
	volume.handlesLock.RUnlock()
	f.fdLock.RLock()
	defer f.fdLock.RUnlock()
	f.contentLock.Lock()
        defer f.contentLock.Unlock()
	n, _ := volume.doWrite(handleID, data, offset)
	return n
}

//export gcf_close_file
func gcf_close_file(sessionID, handleID int) {
	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return
	}
	volume := value.(*Volume)
	volume.handlesLock.Lock()
	f := volume.fileHandles[handleID]
	f.fdLock.Lock()
	f.fd.Close()
	delete(volume.fileHandles, handleID)
	volume.handlesLock.Unlock()
	f.fdLock.Unlock()
}

//export gcf_remove_file
func gcf_remove_file(sessionID int, path string) bool {
	value, ok := OpenedVolumes.Load(sessionID)
	if !ok {
		return false
	}
	volume := value.(*Volume)
	dirfd, cName, err := volume.prepareAtSyscall(path)
	if err != nil {
		return false
	}
	defer syscall.Close(dirfd)

	// Delete content
	err = syscallcompat.Unlinkat(dirfd, cName, 0)
	if err != nil {
		return false
	}
	// Delete ".name" file
	if !volume.plainTextNames && nametransform.IsLongContent(cName) {
		err = nametransform.DeleteLongNameAt(dirfd, cName)
	}
	return errToBool(err)
}
