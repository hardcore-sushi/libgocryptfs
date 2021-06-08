// +build arm64 amd64

package allocator

import (
	"C"
	"unsafe"
)

func Malloc(size int) unsafe.Pointer {
	return C.malloc(C.ulong(C.sizeof_int * size))
}
