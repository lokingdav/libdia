package dia

import (
    "testing"
)

func BenchmarkSetup(b *testing.B) {
    for i := 0; i < b.N; i++ {
        _, _, _, err := Setup()
        if err != nil {
            b.Fatalf("Setup failed: %v", err)
        }
    }
}

func BenchmarkUserKeygen(b *testing.B) {
    // one-time setup
    gpk, _, isk, err := Setup()
    if err != nil {
        b.Fatalf("Setup failed: %v", err)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := UserKeygen(gpk, isk)
        if err != nil {
            b.Fatalf("UserKeygen failed: %v", err)
        }
    }
}

func BenchmarkSign(b *testing.B) {
    gpk, _, isk, err := Setup()
    if err != nil {
        b.Fatalf("Setup failed: %v", err)
    }
    usk, err := UserKeygen(gpk, isk)
    if err != nil {
        b.Fatalf("UserKeygen failed: %v", err)
    }
    msg := []byte("benchmark message")
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := Sign(gpk, usk, msg)
        if err != nil {
            b.Fatalf("Sign failed: %v", err)
        }
    }
}

func BenchmarkVerify(b *testing.B) {
    gpk, _, isk, err := Setup()
    if err != nil {
        b.Fatalf("Setup failed: %v", err)
    }
    usk, err := UserKeygen(gpk, isk)
    if err != nil {
        b.Fatalf("UserKeygen failed: %v", err)
    }
    msg := []byte("benchmark message")
    sig, err := Sign(gpk, usk, msg)
    if err != nil {
        b.Fatalf("Sign failed: %v", err)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        if !Verify(gpk, sig, msg) {
            b.Fatal("Verify returned false")
        }
    }
}

func BenchmarkOpen(b *testing.B) {
    gpk, osk, isk, err := Setup()
    if err != nil {
        b.Fatalf("Setup failed: %v", err)
    }
    usk, err := UserKeygen(gpk, isk)
    if err != nil {
        b.Fatalf("UserKeygen failed: %v", err)
    }
    msg := []byte("benchmark message")
    sig, err := Sign(gpk, usk, msg)
    if err != nil {
        b.Fatalf("Sign failed: %v", err)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := Open(gpk, osk, sig)
        if err != nil {
            b.Fatalf("Open failed: %v", err)
        }
    }
}

func BenchmarkVerifyUsk(b *testing.B) {
    gpk, _, isk, err := Setup()
    if err != nil {
        b.Fatalf("Setup failed: %v", err)
    }
    usk, err := UserKeygen(gpk, isk)
    if err != nil {
        b.Fatalf("UserKeygen failed: %v", err)
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        if !VerifyUsk(gpk, usk) {
            b.Fatal("VerifyUsk returned false")
        }
    }
}

// EC helper benchmarks
func BenchmarkScalarRandom(b *testing.B) {
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := ScalarRandom()
        if err != nil {
            b.Fatalf("ScalarRandom failed: %v", err)
        }
    }
}

func BenchmarkScalarInverse(b *testing.B) {
    // generate one scalar
    scalar, err := ScalarRandom()
    if err != nil {
        b.Fatalf("ScalarRandom failed: %v", err)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := ScalarInverse(scalar)
        if err != nil {
            b.Fatalf("ScalarInverse failed: %v", err)
        }
    }
}

func BenchmarkG1HashToPoint(b *testing.B) {
    msg := []byte("benchmark message")
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := G1HashToPoint(msg)
        if err != nil {
            b.Fatalf("G1HashToPoint failed: %v", err)
        }
    }
}

func BenchmarkG1Mul(b *testing.B) {
    msg := []byte("benchmark message")
    scalar, err := ScalarRandom()
    if err != nil {
        b.Fatalf("ScalarRandom failed: %v", err)
    }
    point, err := G1HashToPoint(msg)
    if err != nil {
        b.Fatalf("G1HashToPoint failed: %v", err)
    }
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := G1Mul(point, scalar)
        if err != nil {
            b.Fatalf("G1Mul failed: %v", err)
        }
    }
}
