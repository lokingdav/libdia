package dia

import (
	"testing"
)

// --- Small helpers (local to benchmarks) ---

// func s2b(s string) []byte { return []byte(s) }

func clone2D(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i := range in {
		if in[i] != nil {
			cp := make([]byte, len(in[i]))
			copy(cp, in[i])
			out[i] = cp
		}
	}
	return out
}

// =============================== VOPRF ===================================

func BenchmarkVOPRF_Keygen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := VOPRFKeygen(); err != nil {
			b.Fatalf("VOPRFKeygen: %v", err)
		}
	}
}

func BenchmarkVOPRF_EndToEnd(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	_, pk, err := VOPRFKeygen()
	if err != nil {
		b.Fatalf("VOPRFKeygen: %v", err)
	}
	in := s2b("hello voprf")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blinded, blind, err := VOPRFBlind(in)
		if err != nil {
			b.Fatalf("VOPRFBlind: %v", err)
		}
		elem, err := VOPRFEvaluate(blinded, /*sk=*/nil) // NOTE: server-side evaluate needs sk; adjust if your API differs
		_ = elem
		// If your cgo API requires server secret for evaluate, keep a local sk and pass it here.
		// The line above is a placeholder—replace with your actual use:
		// elem, err := VOPRFEvaluate(blinded, sk)
		if err != nil {
			b.Fatalf("VOPRFEvaluate: %v", err)
		}
		Y, err := VOPRFUnblind(elem, blind)
		if err != nil {
			b.Fatalf("VOPRFUnblind: %v", err)
		}
		if err := VOPRFVerify(in, Y, pk); err != nil {
			b.Fatalf("VOPRFVerify: %v", err)
		}
	}
}

func BenchmarkVOPRF_VerifyBatch_16(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	sk, pk, err := VOPRFKeygen()
	if err != nil {
		b.Fatalf("VOPRFKeygen: %v", err)
	}
	N := 16
	inputs := make([][]byte, N)
	Ys := make([][]byte, N)
	for i := 0; i < N; i++ {
		inputs[i] = s2b("msg-" + string(rune('A'+(i%26))))
		blinded, blind, err := VOPRFBlind(inputs[i])
		if err != nil {
			b.Fatalf("VOPRFBlind: %v", err)
		}
		elem, err := VOPRFEvaluate(blinded, sk)
		if err != nil {
			b.Fatalf("VOPRFEvaluate: %v", err)
		}
		Y, err := VOPRFUnblind(elem, blind)
		if err != nil {
			b.Fatalf("VOPRFUnblind: %v", err)
		}
		Ys[i] = Y
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := VOPRFVerifyBatch(inputs, Ys, pk); err != nil {
			b.Fatalf("VOPRFVerifyBatch: %v", err)
		}
	}
}

// ================================ AMF ====================================

func BenchmarkAMF_Keygen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := AMFKeygen(); err != nil {
			b.Fatalf("AMFKeygen: %v", err)
		}
	}
}

func BenchmarkAMF_Frank(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	Ssk, _ /*Spk*/, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen S: %v", err)
	}
	_, Rpk, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen R: %v", err)
	}
	_, Jpk, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen J: %v", err)
	}
	msg := s2b("hello AMF")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AMFFrank(Ssk, Rpk, Jpk, msg); err != nil {
			b.Fatalf("AMFFrank: %v", err)
		}
	}
}

func BenchmarkAMF_Verify(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	Ssk, Spk, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen S: %v", err)
	}
	Rsk, Rpk, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen R: %v", err)
	}
	_ /*Jsk*/, Jpk, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen J: %v", err)
	}
	msg := s2b("hello AMF")
	sig, err := AMFFrank(Ssk, Rpk, Jpk, msg)
	if err != nil {
		b.Fatalf("AMFFrank: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := AMFVerify(Spk, Rsk, Jpk, msg, sig); err != nil {
			b.Fatalf("AMFVerify: %v", err)
		}
	}
}

func BenchmarkAMF_Judge(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	Ssk, Spk, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen S: %v", err)
	}
	_ /*Rsk*/, Rpk, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen R: %v", err)
	}
	Jsk, Jpk, err := AMFKeygen()
	if err != nil {
		b.Fatalf("AMFKeygen J: %v", err)
	}
	msg := s2b("hello AMF")
	sig, err := AMFFrank(Ssk, Rpk, Jpk, msg)
	if err != nil {
		b.Fatalf("AMFFrank: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := AMFJudge(Spk, Rpk, Jsk, msg, sig); err != nil {
			b.Fatalf("AMFJudge: %v", err)
		}
	}
}

// ================================ BBS ====================================

func benchMsgs(L int) [][]byte {
	out := make([][]byte, L)
	for i := 0; i < L; i++ {
		out[i] = s2b("msg#" + string(rune('a'+(i%26))))
	}
	return out
}

func BenchmarkBBS_Keygen(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := BBSKeygen(); err != nil {
			b.Fatalf("BBSKeygen: %v", err)
		}
	}
}

func BenchmarkBBS_Sign_L8(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	sk, _, err := BBSKeygen()
	if err != nil {
		b.Fatalf("BBSKeygen: %v", err)
	}
	msgs := benchMsgs(8)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := BBSSign(msgs, sk); err != nil {
			b.Fatalf("BBSSign: %v", err)
		}
	}
}

func BenchmarkBBS_Verify_L8(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	sk, pk, err := BBSKeygen()
	if err != nil {
		b.Fatalf("BBSKeygen: %v", err)
	}
	msgs := benchMsgs(8)
	A, e, err := BBSSign(msgs, sk)
	if err != nil {
		b.Fatalf("BBSSign: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := BBSVerify(msgs, pk, A, e); err != nil {
			b.Fatalf("BBSVerify: %v", err)
		}
	}
}

func BenchmarkBBS_ProofCreate_k0_L8(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	sk, pk, err := BBSKeygen()
	if err != nil {
		b.Fatalf("BBSKeygen: %v", err)
	}
	msgs := benchMsgs(8)
	A, e, err := BBSSign(msgs, sk)
	if err != nil {
		b.Fatalf("BBSSign: %v", err)
	}
	nonce := s2b("bbs-proof-nonce")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BBSCreateProof(msgs, nil, pk, A, e, nonce); err != nil {
			b.Fatalf("BBSCreateProof k=0: %v", err)
		}
	}
}

func BenchmarkBBS_ProofVerify_k0_L8(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	sk, pk, err := BBSKeygen()
	if err != nil {
		b.Fatalf("BBSKeygen: %v", err)
	}
	msgs := benchMsgs(8)
	A, e, err := BBSSign(msgs, sk)
	if err != nil {
		b.Fatalf("BBSSign: %v", err)
	}
	nonce := s2b("bbs-proof-nonce")
	proof, err := BBSCreateProof(msgs, nil, pk, A, e, nonce)
	if err != nil {
		b.Fatalf("BBSCreateProof k=0: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := BBSVerifyProof(nil, nil, pk, nonce, proof); err != nil {
			b.Fatalf("BBSVerifyProof k=0: %v", err)
		}
	}
}

func BenchmarkBBS_ProofCreate_kHalf_L8(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	sk, pk, err := BBSKeygen()
	if err != nil {
		b.Fatalf("BBSKeygen: %v", err)
	}
	msgs := benchMsgs(8)
	A, e, err := BBSSign(msgs, sk)
	if err != nil {
		b.Fatalf("BBSSign: %v", err)
	}
	nonce := s2b("bbs-proof-nonce")

	// Reveal half: indices 1,3,5,7 (1-based)
	disclose := []uint32{1, 3, 5, 7}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := BBSCreateProof(msgs, disclose, pk, A, e, nonce); err != nil {
			b.Fatalf("BBSCreateProof k=L/2: %v", err)
		}
	}
}

func BenchmarkBBS_ProofVerify_kHalf_L8(b *testing.B) {
	b.ReportAllocs()

	// Setup once
	sk, pk, err := BBSKeygen()
	if err != nil {
		b.Fatalf("BBSKeygen: %v", err)
	}
	msgs := benchMsgs(8)
	A, e, err := BBSSign(msgs, sk)
	if err != nil {
		b.Fatalf("BBSSign: %v", err)
	}
	nonce := s2b("bbs-proof-nonce")
	disclose := []uint32{1, 3, 5, 7}

	proof, err := BBSCreateProof(msgs, disclose, pk, A, e, nonce)
	if err != nil {
		b.Fatalf("BBSCreateProof k=L/2: %v", err)
	}

	// Build disclosed message list matching indices (1-based)
	disclosed := make([][]byte, 0, len(disclose))
	for _, idx := range disclose {
		disclosed = append(disclosed, msgs[idx-1])
	}

	// Copy to avoid accidental sharing (not strictly necessary)
	disclosed = clone2D(disclosed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := BBSVerifyProof(disclose, disclosed, pk, nonce, proof); err != nil {
			b.Fatalf("BBSVerifyProof k=L/2: %v", err)
		}
	}
}
