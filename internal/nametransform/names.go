// Package nametransform encrypts and decrypts filenames.
package nametransform

import (
	"crypto/aes"
	"encoding/base64"
	"path/filepath"
	"syscall"

	"github.com/rfjakob/eme"
)

const (
	// Like ext4, we allow at most 255 bytes for a file name.
	NameMax = 255
)

// NameTransform is used to transform filenames.
type NameTransform struct {
	emeCipher *eme.EMECipher
	longNames bool
	// B64 = either base64.URLEncoding or base64.RawURLEncoding, depending
	// on the Raw64 feature flag
	B64 *base64.Encoding
	// Patterns to bypass decryption
	badnamePatterns []string
}

// New returns a new NameTransform instance.
func New(e *eme.EMECipher, longNames bool, raw64 bool, badname []string) *NameTransform {
	b64 := base64.URLEncoding
	if raw64 {
		b64 = base64.RawURLEncoding
	}
	return &NameTransform{
		emeCipher:       e,
		longNames:       longNames,
		B64:             b64,
		badnamePatterns: badname,
	}
}

// DecryptName calls decryptName to try and decrypt a base64-encoded encrypted
// filename "cipherName", and failing that checks if it can be bypassed
func (n *NameTransform) DecryptName(cipherName string, iv []byte) (string, error) {
	res, err := n.decryptName(cipherName, iv)
	if err != nil && n.HaveBadnamePatterns() {
		return n.decryptBadname(cipherName, iv)
	}
	return res, err
}

// decryptName decrypts a base64-encoded encrypted filename "cipherName" using the
// initialization vector "iv".
func (n *NameTransform) decryptName(cipherName string, iv []byte) (string, error) {
	bin, err := n.B64.DecodeString(cipherName)
	if err != nil {
		return "", err
	}
	if len(bin) == 0 {
		return "", syscall.EBADMSG
	}
	if len(bin)%aes.BlockSize != 0 {
		return "", syscall.EBADMSG
	}
	bin = n.emeCipher.Decrypt(iv, bin)
	bin, err = unPad16(bin)
	if err != nil {
		return "", syscall.EBADMSG
	}
	plain := string(bin)
	if err := IsValidName(plain); err != nil {
		return "", syscall.EBADMSG
	}
	return plain, err
}

// EncryptName encrypts "plainName", returns a base64-encoded "cipherName64",
// encrypted using EME (https://github.com/rfjakob/eme).
//
// This function is exported because in some cases, fusefrontend needs access
// to the full (not hashed) name if longname is used.
func (n *NameTransform) EncryptName(plainName string, iv []byte) (cipherName64 string, err error) {
	if err := IsValidName(plainName); err != nil {
		return "", syscall.EBADMSG
	}
	bin := []byte(plainName)
	bin = pad16(bin)
	bin = n.emeCipher.Encrypt(iv, bin)
	cipherName64 = n.B64.EncodeToString(bin)
	return cipherName64, nil
}

// EncryptAndHashName encrypts "name" and hashes it to a longname if it is
// too long.
// Returns ENAMETOOLONG if "name" is longer than 255 bytes.
func (be *NameTransform) EncryptAndHashName(name string, iv []byte) (string, error) {
	// Prevent the user from creating files longer than 255 chars.
	if len(name) > NameMax {
		return "", syscall.ENAMETOOLONG
	}
	cName, err := be.EncryptName(name, iv)
	if err != nil {
		return "", err
	}
	if be.longNames && len(cName) > NameMax {
		return be.HashLongName(cName), nil
	}
	return cName, nil
}

// B64EncodeToString returns a Base64-encoded string
func (n *NameTransform) B64EncodeToString(src []byte) string {
	return n.B64.EncodeToString(src)
}

// B64DecodeString decodes a Base64-encoded string
func (n *NameTransform) B64DecodeString(s string) ([]byte, error) {
	return n.B64.DecodeString(s)
}

// Dir is like filepath.Dir but returns "" instead of ".".
func Dir(path string) string {
	d := filepath.Dir(path)
	if d == "." {
		return ""
	}
	return d
}
