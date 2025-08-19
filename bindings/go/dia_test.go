package dia

import (
	"bytes"
	"testing"
)

func s2b(s string) []byte { return []byte(s) }

// ------------------------------- VOPRF --------------------------------

func TestVOPRF_EndToEnd(t *testing.T) {
	// Keygen (server)
	sk, pk, err := VOPRFKeygen()
	if err != nil {
		t.Fatalf("VOPRFKeygen: %v", err)
	}

	input := s2b("hello voprf")

	// Client blinds
	blinded, blind, err := VOPRFBlind(input)
	if err != nil {
		t.Fatalf("VOPRFBlind: %v", err)
	}

	// Server evaluates
	elem, err := VOPRFEvaluate(blinded, sk)
	if err != nil {
		t.Fatalf("VOPRFEvaluate: %v", err)
	}

	// Client unblinds, then verifies result against server pk
	Y, err := VOPRFUnblind(elem, blind)
	if err != nil {
		t.Fatalf("VOPRFUnblind: %v", err)
	}
	if err := VOPRFVerify(input, Y, pk); err != nil {
		t.Fatalf("VOPRFVerify: %v", err)
	}

	// Negative: wrong input should fail verify
	if err := VOPRFVerify(s2b("different"), Y, pk); err == nil {
		t.Fatalf("VOPRFVerify should fail on different input")
	}
}

func TestVOPRF_Batch16(t *testing.T) {
	sk, pk, err := VOPRFKeygen()
	if err != nil {
		t.Fatalf("VOPRFKeygen: %v", err)
	}

	const N = 16
	inputs := make([][]byte, N)
	Ys := make([][]byte, N)

	for i := 0; i < N; i++ {
		inputs[i] = s2b("msg-" + string(rune('A'+i)))
		blinded, blind, err := VOPRFBlind(inputs[i])
		if err != nil {
			t.Fatalf("VOPRFBlind[%d]: %v", i, err)
		}
		elem, err := VOPRFEvaluate(blinded, sk)
		if err != nil {
			t.Fatalf("VOPRFEvaluate[%d]: %v", i, err)
		}
		Y, err := VOPRFUnblind(elem, blind)
		if err != nil {
			t.Fatalf("VOPRFUnblind[%d]: %v", i, err)
		}
		Ys[i] = Y
	}

	if err := VOPRFVerifyBatch(inputs, Ys, pk); err != nil {
		t.Fatalf("VOPRFVerifyBatch: %v", err)
	}
}

// -------------------------------- AMF ---------------------------------

func TestAMF_EndToEnd_And_Negatives(t *testing.T) {
	// Parties: Sender (S), Receiver (R), Judge (J)
	Ssk, Spk, err := AMFKeygen()
	if err != nil {
		t.Fatalf("AMFKeygen S: %v", err)
	}
	Rsk, Rpk, err := AMFKeygen()
	if err != nil {
		t.Fatalf("AMFKeygen R: %v", err)
	}
	Jsk, Jpk, err := AMFKeygen()
	if err != nil {
		t.Fatalf("AMFKeygen J: %v", err)
	}

	msg := s2b("hello AMF")

	// Frank
	sig, err := AMFFrank(Ssk, Rpk, Jpk, msg)
	if err != nil {
		t.Fatalf("AMFFrank: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("AMFFrank: empty signature blob")
	}

	// Verify & Judge succeed
	if err := AMFVerify(Spk, Rsk, Jpk, msg, sig); err != nil {
		t.Fatalf("AMFVerify: %v", err)
	}
	if err := AMFJudge(Spk, Rpk, Jsk, msg, sig); err != nil {
		t.Fatalf("AMFJudge: %v", err)
	}

	// Negative: different message
	if err := AMFVerify(Spk, Rsk, Jpk, s2b("different"), sig); err == nil {
		t.Fatalf("AMFVerify should fail with different message")
	}
	if err := AMFJudge(Spk, Rpk, Jsk, s2b("different"), sig); err == nil {
		t.Fatalf("AMFJudge should fail with different message")
	}

	// Negative: wrong sender pk
	_, Spk2, err := AMFKeygen()
	if err != nil {
		t.Fatalf("AMFKeygen S2: %v", err)
	}
	if err := AMFVerify(Spk2, Rsk, Jpk, msg, sig); err == nil {
		t.Fatalf("AMFVerify should fail with wrong sender pk")
	}
	if err := AMFJudge(Spk2, Rpk, Jsk, msg, sig); err == nil {
		t.Fatalf("AMFJudge should fail with wrong sender pk")
	}

	// Negative: wrong receiver secret → Verify fails, Judge still passes
	Rsk2, Rpk2, err := AMFKeygen()
	if err != nil {
		t.Fatalf("AMFKeygen R2: %v", err)
	}
	if err := AMFVerify(Spk, Rsk2, Jpk, msg, sig); err == nil {
		t.Fatalf("AMFVerify should fail with wrong receiver secret")
	}
	if err := AMFJudge(Spk, Rpk, Jsk, msg, sig); err != nil {
		t.Fatalf("AMFJudge should still pass with wrong receiver secret: %v", err)
	}
	_ = Rpk2 // unused, but kept for symmetry

	// Negative: tamper blob → Verify must fail (parse or check)
	tam := append([]byte(nil), sig...)
	tam[len(tam)/2] ^= 0x01
	if bytes.Equal(tam, sig) {
		t.Fatal("tamper failed (equal blobs)")
	}
	if err := AMFVerify(Spk, Rsk, Jpk, msg, tam); err == nil {
		t.Fatalf("AMFVerify should fail on tampered blob")
	}
}

// -------------------------------- BBS ----------------------------------

func makeMsgs(L int) [][]byte {
	out := make([][]byte, L)
	for i := 0; i < L; i++ {
		out[i] = s2b("m" + string(rune('0'+(i%10))))
	}
	return out
}

func TestBBS_Sign_Verify_Proofs(t *testing.T) {
	// Keygen
	sk, pk, err := BBSKeygen()
	if err != nil {
		t.Fatalf("BBSKeygen: %v", err)
	}

	// Messages
	const L = 8
	msgs := makeMsgs(L)

	// Sign and verify
	A, e, err := BBSSign(msgs, sk)
	if err != nil {
		t.Fatalf("BBSSign: %v", err)
	}
	if err := BBSVerify(msgs, pk, A, e); err != nil {
		t.Fatalf("BBSVerify: %v", err)
	}

	// Proof: reveal none (k=0)
	nonce := s2b("bbs-proof-nonce")
	proof0, err := BBSCreateProof(msgs, nil, pk, A, e, nonce)
	if err != nil {
		t.Fatalf("BBSCreateProof k=0: %v", err)
	}
	if len(proof0) == 0 {
		t.Fatalf("proof blob empty")
	}
	if err := BBSVerifyProof(nil, nil, pk, nonce, proof0); err != nil {
		t.Fatalf("BBSVerifyProof k=0: %v", err)
	}

	// Proof: reveal subset {1,3,6} (1-based)
	disclose := []uint32{1, 3, 6}
	proofS, err := BBSCreateProof(msgs, disclose, pk, A, e, nonce)
	if err != nil {
		t.Fatalf("BBSCreateProof subset: %v", err)
	}
	disclosedMsgs := [][]byte{msgs[0], msgs[2], msgs[5]}
	if err := BBSVerifyProof(disclose, disclosedMsgs, pk, nonce, proofS); err != nil {
		t.Fatalf("BBSVerifyProof subset: %v", err)
	}

	// Negative: wrong nonce
	if err := BBSVerifyProof(disclose, disclosedMsgs, pk, s2b("wrong"), proofS); err == nil {
		t.Fatalf("BBSVerifyProof should fail with wrong nonce")
	}

	// Negative: wrong pk
	_, pk2, err := BBSKeygen()
	if err != nil {
		t.Fatalf("BBSKeygen2: %v", err)
	}
	if err := BBSVerifyProof(disclose, disclosedMsgs, pk2, nonce, proofS); err == nil {
		t.Fatalf("BBSVerifyProof should fail with wrong pk")
	}

	// Negative: tamper proof
	tam := append([]byte(nil), proofS...)
	tam[len(tam)/3] ^= 0x01
	if bytes.Equal(tam, proofS) {
		t.Fatal("tamper failed (equal blobs)")
	}
	if err := BBSVerifyProof(disclose, disclosedMsgs, pk, nonce, tam); err == nil {
		t.Fatalf("BBSVerifyProof should fail on tampered proof")
	}
}
