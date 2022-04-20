package main

import (
	"log"
	"sync"
	"syscall"
	"time"
)

const (
	// Number of entries in the dirCache.
	// 20 entries work well for "git stat" on a small git repo on sshfs.
	// Keep in sync with test_helpers.maxCacheFds !
	// TODO: How to share this constant without causing an import cycle?
	dirCacheSize = 20
	// Enable Lookup/Store/Clear debug messages
	enableDebugMessages = false
	// Enable hit rate statistics printing
	enableStats = false
)

type dirCacheEntry struct {
	path string
	// fd to the directory (opened with O_PATH!)
	fd int
	// content of gocryptfs.diriv in this directory
	iv []byte
}

func (e *dirCacheEntry) Clear() {
	// An earlier clear may have already closed the fd, or the cache
	// has never been filled (fd is 0 in that case).
	// Note: package ensurefds012, imported from main, guarantees that dirCache
	// can never get fds 0,1,2.
	if e.fd > 0 {
		syscall.Close(e.fd)
	}
	e.fd = -1
	e.path = ""
	e.iv = nil
}

type dirCache struct {
	sync.Mutex
	// Expected length of the stored IVs. Only used for sanity checks.
	// Usually set to 16, but 0 in plaintextnames mode.
	ivLen int
	// Cache entries
	entries [dirCacheSize]dirCacheEntry
	// Where to store the next entry (index into entries)
	nextIndex int
	// On the first Lookup(), the expire thread is started, and this flag is set
	// to true.
	expireThreadRunning bool
	// Hit rate stats. Evaluated and reset by the expire thread.
	lookups uint64
	hits    uint64
}

// Clear clears the cache contents.
func (d *dirCache) Clear() {
	d.Lock()
	defer d.Unlock()
	for i := range d.entries {
		d.entries[i].Clear()
	}
}

// Store the entry in the cache. The passed "fd" will be Dup()ed, and the caller
// can close their copy at will.
func (d *dirCache) Store(path string, fd int, iv []byte) {
	// Note: package ensurefds012, imported from main, guarantees that dirCache
	// can never get fds 0,1,2.
	if fd <= 0 || len(iv) != d.ivLen {
		log.Panicf("Store sanity check failed: fd=%d len=%d", fd, len(iv))
	}
	d.Lock()
	defer d.Unlock()
	e := &d.entries[d.nextIndex]
	// Round-robin works well enough
	d.nextIndex = (d.nextIndex + 1) % dirCacheSize
	// Close the old fd
	e.Clear()
	fd2, err := syscall.Dup(fd)
	if err != nil {
		return
	}
	e.fd = fd2
	e.path = string([]byte(path[:]))
	e.iv = iv
	// expireThread is started on the first Lookup()
	if !d.expireThreadRunning {
		d.expireThreadRunning = true
		go d.expireThread()
	}
}

// Lookup checks if relPath is in the cache, and returns an (fd, iv) pair.
// It returns (-1, nil) if not found. The fd is internally Dup()ed and the
// caller must close it when done.
func (d *dirCache) Lookup(path string) (fd int, iv []byte) {
	d.Lock()
	defer d.Unlock()
	if enableStats {
		d.lookups++
	}
	var e *dirCacheEntry
	for i := range d.entries {
		e = &d.entries[i]
		if e.fd <= 0 {
			// Cache slot is empty
			continue
		}
		if path != e.path {
			// Not the right path
			continue
		}
		var err error
		fd, err = syscall.Dup(e.fd)
		if err != nil {
			return -1, nil
		}
		iv = e.iv
		break
	}
	if fd == 0 {
		return -1, nil
	}
	if enableStats {
		d.hits++
	}
	if fd <= 0 || len(iv) != d.ivLen {
		log.Panicf("Lookup sanity check failed: fd=%d len=%d", fd, len(iv))
	}
	return fd, iv
}

// expireThread is started on the first Lookup()
func (d *dirCache) expireThread() {
	for {
		time.Sleep(60 * time.Second)
		d.Clear()
	}
}

func (d* dirCache) Delete(path string) {
	for i := range d.entries {
		e := &d.entries[i]
		if e.path == path {
			e.Clear()
			break
		}
	}
}
