package dia

/*
#cgo pkg-config: --static dia
#include <dia/dia_c.h>
#include <stdlib.h>
*/
import "C"
// import (
// 	"errors"
// 	"unsafe"
// )

// InitDia wraps init_dia. Must be called before any other call.
func InitDia() {
	C.init_dia()
}