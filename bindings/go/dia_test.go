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
	ok, err := VOPRFVerify(input, Y, pk)
	if err != nil {
		t.Fatalf("VOPRFVerify: %v", err)
	}
	if !ok {
		t.Fatalf("VOPRFVerify: expected valid")
	}

	// Negative: wrong input should report invalid (no API error)
	ok, err = VOPRFVerify(s2b("different"), Y, pk)
	if err != nil {
		t.Fatalf("VOPRFVerify(different): unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("VOPRFVerify should be invalid on different input")
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

	ok, err := VOPRFVerifyBatch(inputs, Ys, pk)
	if err != nil {
		t.Fatalf("VOPRFVerifyBatch: %v", err)
	}
	if !ok {
		t.Fatalf("VOPRFVerifyBatch: expected all valid")
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
	ok, err := AMFVerify(Spk, Rsk, Jpk, msg, sig)
	if err != nil {
		t.Fatalf("AMFVerify: %v", err)
	}
	if !ok {
		t.Fatalf("AMFVerify: expected valid")
	}
	ok, err = AMFJudge(Spk, Rpk, Jsk, msg, sig)
	if err != nil {
		t.Fatalf("AMFJudge: %v", err)
	}
	if !ok {
		t.Fatalf("AMFJudge: expected valid")
	}

	// Negative: different message
	ok, err = AMFVerify(Spk, Rsk, Jpk, s2b("different"), sig)
	if err != nil {
		t.Fatalf("AMFVerify(different): %v", err)
	}
	if ok {
		t.Fatalf("AMFVerify should be invalid with different message")
	}
	ok, err = AMFJudge(Spk, Rpk, Jsk, s2b("different"), sig)
	if err != nil {
		t.Fatalf("AMFJudge(different): %v", err)
	}
	if ok {
		t.Fatalf("AMFJudge should be invalid with different message")
	}

	// Negative: wrong sender pk
	_, Spk2, err := AMFKeygen()
	if err != nil {
		t.Fatalf("AMFKeygen S2: %v", err)
	}
	ok, err = AMFVerify(Spk2, Rsk, Jpk, msg, sig)
	if err != nil {
		t.Fatalf("AMFVerify(wrong sender): %v", err)
	}
	if ok {
		t.Fatalf("AMFVerify should be invalid with wrong sender pk")
	}
	ok, err = AMFJudge(Spk2, Rpk, Jsk, msg, sig)
	if err != nil {
		t.Fatalf("AMFJudge(wrong sender): %v", err)
	}
	if ok {
		t.Fatalf("AMFJudge should be invalid with wrong sender pk")
	}

	// Negative: wrong receiver secret → Verify invalid, Judge still valid
	Rsk2, Rpk2, err := AMFKeygen()
	if err != nil {
		t.Fatalf("AMFKeygen R2: %v", err)
	}
	ok, err = AMFVerify(Spk, Rsk2, Jpk, msg, sig)
	if err != nil {
		t.Fatalf("AMFVerify(wrong receiver sk): %v", err)
	}
	if ok {
		t.Fatalf("AMFVerify should be invalid with wrong receiver secret")
	}
	ok, err = AMFJudge(Spk, Rpk, Jsk, msg, sig)
	if err != nil {
		t.Fatalf("AMFJudge (independent of sk_r) unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("AMFJudge should still pass with wrong receiver secret")
	}
	_ = Rpk2 // keep for symmetry

	// Negative: tamper blob → must be invalid (either parse error OR parsed-invalid)
	tam := append([]byte(nil), sig...)
	tam[len(tam)/2] ^= 0x01
	if bytes.Equal(tam, sig) {
		t.Fatal("tamper failed (equal blobs)")
	}
	ok, err = AMFVerify(Spk, Rsk, Jpk, msg, tam)
	if err == nil && ok {
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

	// Sign and verify (opaque signature blob)
	sig, err := BBSSign(msgs, sk)
	if err != nil {
		t.Fatalf("BBSSign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatalf("BBSSign: empty signature blob")
	}
	ok, err := BBSVerify(msgs, pk, sig)
	if err != nil {
		t.Fatalf("BBSVerify: %v", err)
	}
	if !ok {
		t.Fatalf("BBSVerify: expected valid")
	}

	// Proof: reveal none (k=0)
	nonce := s2b("bbs-proof-nonce")
	proof0, err := BBSCreateProof(msgs, nil, pk, sig, nonce)
	if err != nil {
		t.Fatalf("BBSCreateProof k=0: %v", err)
	}
	if len(proof0) == 0 {
		t.Fatalf("proof blob empty")
	}
	ok, err = BBSVerifyProof(nil, nil, pk, nonce, proof0)
	if err != nil {
		t.Fatalf("BBSVerifyProof k=0: %v", err)
	}
	if !ok {
		t.Fatalf("BBSVerifyProof k=0: expected valid")
	}

	// Proof: reveal subset {1,3,6} (1-based)
	disclose := []uint32{1, 3, 6}
	proofS, err := BBSCreateProof(msgs, disclose, pk, sig, nonce)
	if err != nil {
		t.Fatalf("BBSCreateProof subset: %v", err)
	}
	disclosedMsgs := [][]byte{msgs[0], msgs[2], msgs[5]}
	ok, err = BBSVerifyProof(disclose, disclosedMsgs, pk, nonce, proofS)
	if err != nil {
		t.Fatalf("BBSVerifyProof subset: %v", err)
	}
	if !ok {
		t.Fatalf("BBSVerifyProof subset: expected valid")
	}

	// Negative: wrong nonce → invalid
	ok, err = BBSVerifyProof(disclose, disclosedMsgs, pk, s2b("wrong"), proofS)
	if err != nil {
		t.Fatalf("BBSVerifyProof wrong nonce: %v", err)
	}
	if ok {
		t.Fatalf("BBSVerifyProof should be invalid with wrong nonce")
	}

	// Negative: wrong pk → invalid
	_, pk2, err := BBSKeygen()
	if err != nil {
		t.Fatalf("BBSKeygen2: %v", err)
	}
	ok, err = BBSVerifyProof(disclose, disclosedMsgs, pk2, nonce, proofS)
	if err != nil {
		t.Fatalf("BBSVerifyProof wrong pk: %v", err)
	}
	if ok {
		t.Fatalf("BBSVerifyProof should be invalid with wrong pk")
	}

	// Negative: tamper proof → invalid (either parse error OR parsed-invalid)
	tam := append([]byte(nil), proofS...)
	tam[len(tam)/3] ^= 0x01
	if bytes.Equal(tam, proofS) {
		t.Fatal("tamper failed (equal blobs)")
	}
	ok, err = BBSVerifyProof(disclose, disclosedMsgs, pk, nonce, tam)
	if err == nil && ok {
		t.Fatalf("BBSVerifyProof should fail on tampered proof")
	}
}
