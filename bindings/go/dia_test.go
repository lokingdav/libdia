package dia

import "testing"

func TestDiaEndToEnd(t *testing.T) {
    InitDia()
}

// equalBytes is a helper to compare two byte slices
func equalBytes(a, b []byte) bool {
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}
