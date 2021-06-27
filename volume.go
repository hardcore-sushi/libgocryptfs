// gocryptfs is an encrypted overlay filesystem written in Go.
// See README.md ( https://github.com/rfjakob/gocryptfs/blob/master/README.md )
// and the official website ( https://nuetzlich.net/gocryptfs/ ) for details.
package main

import (
	"C"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"./internal/configfile"
	"./internal/contentenc"
	"./internal/cryptocore"
	"./internal/nametransform"
	"./internal/stupidgcm"
	"./internal/syscallcompat"
)

type Directory struct {
	fd int
	iv []byte
}

type File struct {
	fd   *os.File
	path string
}

type Volume struct {
	volumeID       int
	rootCipherDir  string
	plainTextNames bool
	nameTransform  *nametransform.NameTransform
	cryptoCore     *cryptocore.CryptoCore
	contentEnc     *contentenc.ContentEnc
	dirCache       map[string]Directory
	file_handles   map[int]File
	fileIDs        map[int][]byte
}

var OpenedVolumes map[int]Volume

func wipe(d []byte) {
	for i := range d {
		d[i] = 0
	}
	d = nil
}

func clearDirCache(volumeID int) {
	for k := range OpenedVolumes[volumeID].dirCache {
		delete(OpenedVolumes[volumeID].dirCache, k)
	}
}

func errToBool(err error) bool {
	return err == nil
}

func registerNewVolume(rootCipherDir string, masterkey []byte, cf *configfile.ConfFile) int {
	var newVolume Volume

	newVolume.plainTextNames = cf.IsFeatureFlagSet(configfile.FlagPlaintextNames)

	// Init crypto backend
	cryptoBackend := cryptocore.BackendGoGCM
	if cf.IsFeatureFlagSet(configfile.FlagAESSIV) {
		cryptoBackend = cryptocore.BackendAESSIV
	} else if stupidgcm.PreferOpenSSL() {
		cryptoBackend = cryptocore.BackendOpenSSL
	}
	forcedecode := false
	newVolume.cryptoCore = cryptocore.New(masterkey, cryptoBackend, contentenc.DefaultIVBits, true, forcedecode)
	newVolume.contentEnc = contentenc.New(newVolume.cryptoCore, contentenc.DefaultBS, forcedecode)
	var badname []string
	newVolume.nameTransform = nametransform.New(newVolume.cryptoCore.EMECipher, true, true, badname)

	//copying rootCipherDir
	var grcd strings.Builder
	grcd.WriteString(rootCipherDir)
	newVolume.rootCipherDir = grcd.String()

	// New empty caches
	newVolume.dirCache = make(map[string]Directory)
	newVolume.file_handles = make(map[int]File)
	newVolume.fileIDs = make(map[int][]byte)

	//find unused volumeID
	volumeID := -1
	c := 0
	for volumeID == -1 {
		_, ok := OpenedVolumes[c]
		if !ok {
			volumeID = c
		}
		c++
	}
	if OpenedVolumes == nil {
		OpenedVolumes = make(map[int]Volume)
	}
	OpenedVolumes[volumeID] = newVolume
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
	OpenedVolumes[volumeID].cryptoCore.Wipe()
	for handleID := range OpenedVolumes[volumeID].file_handles {
		gcf_close_file(volumeID, handleID)
	}
	clearDirCache(volumeID)
	delete(OpenedVolumes, volumeID)
}

//export gcf_is_closed
func gcf_is_closed(volumeID int) bool {
	_, ok := OpenedVolumes[volumeID]
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
func gcf_create_volume(rootCipherDir string, password []byte, plaintextNames bool, logN int, creator string) bool {
	err := configfile.Create(filepath.Join(rootCipherDir, configfile.ConfDefaultName), password, plaintextNames, logN, creator, false, false, nil, nil)
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
