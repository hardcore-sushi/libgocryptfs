// +build !arm64
// +build !amd64

package allocator

import (
	"C"
	"unsafe"
)

func Malloc(size int) unsafe.Pointer {
	return C.malloc(C.uint(C.sizeof_int * size))
}
