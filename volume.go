// gocryptfs is an encrypted overlay filesystem written in Go.
// See README.md ( https://github.com/rfjakob/gocryptfs/blob/master/README.md )
// and the official website ( https://nuetzlich.net/gocryptfs/ ) for details.
package main

import (
	"C"
	"os"
	"sync"
	"syscall"
	"path/filepath"

	"libgocryptfs/v2/internal/configfile"
	"libgocryptfs/v2/internal/contentenc"
	"libgocryptfs/v2/internal/cryptocore"
	"libgocryptfs/v2/internal/nametransform"
	"libgocryptfs/v2/internal/stupidgcm"
	"libgocryptfs/v2/internal/syscallcompat"
)

type File struct {
	fd          *os.File
	path        string
	ID          []byte
	// fdLock prevents the fd to be closed while we are in the middle of
	// an operation.
	// Every FUSE entrypoint should RLock(). The only user of Lock() is
	// Release(), which closes the fd and sets "released" to true.
	fdLock      sync.RWMutex
	// ContentLock protects on-disk content from concurrent writes. Every writer
	// must take this lock before modifying the file content.
	contentLock sync.RWMutex
}

type Volume struct {
	volumeID       int
	rootCipherDir  string
	plainTextNames bool
	// dirIVLock: Lock()ed if any "gocryptfs.diriv" file is modified
	// Readers must RLock() it to prevent them from seeing intermediate
	// states
	dirIVLock      sync.RWMutex
	nameTransform  *nametransform.NameTransform
	cryptoCore     *cryptocore.CryptoCore
	contentEnc     *contentenc.ContentEnc
	dirCache       dirCache
	file_handles   sync.Map
}

var OpenedVolumes sync.Map

func wipe(d []byte) {
	for i := range d {
		d[i] = 0
	}
	d = nil
}

func errToBool(err error) bool {
	return err == nil
}

func registerNewVolume(rootCipherDir string, masterkey []byte, cf *configfile.ConfFile) int {
	var newVolume Volume

	newVolume.plainTextNames = cf.IsFeatureFlagSet(configfile.FlagPlaintextNames)

	cryptoBackend, err := cf.ContentEncryption()
	if err != nil {
		return -1
	}
	if cryptoBackend == cryptocore.BackendXChaCha20Poly1305 && stupidgcm.PreferOpenSSLXchacha20poly1305() {
		cryptoBackend = cryptocore.BackendXChaCha20Poly1305OpenSSL
	} else if cryptoBackend == cryptocore.BackendGoGCM && stupidgcm.PreferOpenSSLAES256GCM() {
		cryptoBackend = cryptocore.BackendOpenSSL
	}
	newVolume.cryptoCore = cryptocore.New(masterkey, cryptoBackend, cryptoBackend.NonceSize*8, cf.IsFeatureFlagSet(configfile.FlagHKDF))
	newVolume.contentEnc = contentenc.New(newVolume.cryptoCore, contentenc.DefaultBS)
	var badname []string
	newVolume.nameTransform = nametransform.New(
		newVolume.cryptoCore.EMECipher,
		true,
		cf.IsFeatureFlagSet(configfile.FlagRaw64),
		badname,
		!cf.IsFeatureFlagSet(configfile.FlagDirIV),
	)

	//copying rootCipherDir
	newVolume.rootCipherDir = string([]byte(rootCipherDir[:]))

	ivLen := nametransform.DirIVLen
	if newVolume.plainTextNames {
		ivLen = 0
	}
	newVolume.dirCache = dirCache{ivLen: ivLen}

	//find unused volumeID
	volumeID := -1
	c := 0
	for volumeID == -1 {
		_, ok := OpenedVolumes.Load(c)
		if !ok {
			volumeID = c
		}
		c++
	}
	OpenedVolumes.Store(volumeID, &newVolume)
	return volumeID
}

//export gcf_init
func gcf_init(rootCipherDir string, password, givenScryptHash, returnedScryptHashBuff []byte) int {
	volumeID := -1
	cf, err := configfile.Load(filepath.Join(rootCipherDir, configfile.ConfDefaultName))
	if err == nil {
		masterkey := cf.GetMasterkey(password, givenScryptHash, returnedScryptHashBuff)
		if masterkey != nil {
			volumeID = registerNewVolume(rootCipherDir, masterkey, cf)
			wipe(masterkey)
		}
	}
	return volumeID
}

//export gcf_close
func gcf_close(volumeID int) {
	value, ok := OpenedVolumes.Load(volumeID)
	if !ok {
		return
	}
	volume := value.(*Volume)
	volume.cryptoCore.Wipe()
	volume.file_handles.Range(func (handleID, _ interface {}) bool {
		gcf_close_file(volumeID, handleID.(int))
		return true
	})
	volume.dirCache.Clear()
	OpenedVolumes.Delete(volumeID)
}

//export gcf_is_closed
func gcf_is_closed(volumeID int) bool {
	_, ok := OpenedVolumes.Load(volumeID)
	return !ok
}

//export gcf_change_password
func gcf_change_password(rootCipherDir string, oldPassword, givenScryptHash, new_password, returnedScryptHashBuff []byte) bool {
	success := false
	cf, err := configfile.Load(filepath.Join(rootCipherDir, configfile.ConfDefaultName))
	if err == nil {
		masterkey := cf.GetMasterkey(oldPassword, givenScryptHash, nil)
		if masterkey != nil {
			logN := cf.ScryptObject.LogN()
			scryptHash := cf.EncryptKey(masterkey, new_password, logN, len(returnedScryptHashBuff) > 0)
			wipe(masterkey)
			for i := range scryptHash {
				returnedScryptHashBuff[i] = scryptHash[i]
				scryptHash[i] = 0
			}
			success = errToBool(cf.WriteFile())
		}
	}
	return success
}

//export gcf_create_volume
func gcf_create_volume(rootCipherDir string, password []byte, plaintextNames bool, xchacha int8, logN int, creator string, returnedScryptHashBuff []byte) bool {
	var useXChaCha bool
	switch xchacha {
	case 1:
		useXChaCha = true
	case 0:
		useXChaCha = false
	default:
		useXChaCha = !stupidgcm.CpuHasAES()
	}
	err := configfile.Create(&configfile.CreateArgs{
		Filename:           filepath.Join(rootCipherDir, configfile.ConfDefaultName),
		Password:           password,
		PlaintextNames:     plaintextNames,
		LogN:               logN,
		Creator:            creator,
		AESSIV:             false,
		DeterministicNames: false,
		XChaCha20Poly1305:  useXChaCha,
	}, returnedScryptHashBuff)
	if err == nil {
		if plaintextNames {
			return true
		} else {
			dirfd, err := syscall.Open(rootCipherDir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
			if err == nil {
				err = nametransform.WriteDirIVAt(dirfd)
				syscall.Close(dirfd)
				return errToBool(err)
			}
		}
	}
	return false
}
