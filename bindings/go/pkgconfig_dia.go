//go:build !dia_dev

package dia

/*
#cgo pkg-config: dia
// libdia's benchmark/stats uses sqrt() (libm). Some linkers require an explicit -lm.
#cgo LDFLAGS: -lm
*/
import "C"
