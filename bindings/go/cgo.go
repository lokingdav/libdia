package dia

/*
#cgo pkg-config: --static dia
#include <dia/dia_c.h>
#include <stdlib.h>

// Expose compile-time sizes as enum constants so cgo can read them.
enum {
  DIA_FR_LEN_ = DIA_FR_LEN,
  DIA_G1_LEN_ = DIA_G1_LEN,
  DIA_G2_LEN_ = DIA_G2_LEN,
  DIA_GT_LEN_ = DIA_GT_LEN,
  DIA_OK_     = DIA_OK,
  DIA_ERR_    = DIA_ERR
};
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// one-time init of the underlying library (not exported)
var initOnce sync.Once

func ensureInit() {
	initOnce.Do(func() {
		C.init_dia()
	})
}

// Size constants (from C macros via enum bridge)
const (
	FrLen = int(C.DIA_FR_LEN_)
	G1Len = int(C.DIA_G1_LEN_)
	G2Len = int(C.DIA_G2_LEN_)
	GTLen = int(C.DIA_GT_LEN_)
)

func rcErr(op string, rc C.int) error {
	if rc == C.DIA_OK_ {
		return nil
	}
	return fmt.Errorf("%s failed: rc=%d", op, int(rc))
}

/* ================================ Diffie Helman ================================ */

// DHKeygen -> (sk Fr, pk G1)
func DHKeygen() (a []byte, A []byte, err error) {
	ensureInit()
	a = make([]byte, FrLen)
	A = make([]byte, G1Len)
	rc := C.dia_dh_keygen((*C.uchar)(&a[0]), (*C.uchar)(&A[0]))
	return a, A, rcErr("dia_dh_keygen", rc)
}

// DHComputeSecret -> element G1
func DHComputeSecret(a, B []byte) (secret []byte, err error) {
	ensureInit()
	if len(B) != G1Len || len(a) != FrLen {
		return nil, errors.New("DHComputeSecret: bad input sizes")
	}
	secret = make([]byte, G1Len)
	rc := C.dia_dh_compute_secret((*C.uchar)(&secret[0]), (*C.uchar)(&a[0]),
		(*C.uchar)(&B[0]))
	return secret, rcErr("dia_dh_compute_secret", rc)
}

/* ================================ VOPRF ================================ */

// VOPRFKeygen -> (sk Fr, pk G2)
func VOPRFKeygen() (sk []byte, pk []byte, err error) {
	ensureInit()
	sk = make([]byte, FrLen)
	pk = make([]byte, G2Len)
	rc := C.dia_voprf_keygen((*C.uchar)(&sk[0]), (*C.uchar)(&pk[0]))
	return sk, pk, rcErr("dia_voprf_keygen", rc)
}

// VOPRFBlind -> (blinded G1, blind Fr)
func VOPRFBlind(input []byte) (blinded []byte, blind []byte, err error) {
	ensureInit()
	blinded = make([]byte, G1Len)
	blind = make([]byte, FrLen)
	var inPtr *C.uchar
	if len(input) > 0 {
		inPtr = (*C.uchar)(unsafe.Pointer(&input[0]))
	}
	rc := C.dia_voprf_blind(inPtr, C.size_t(len(input)),
		(*C.uchar)(&blinded[0]), (*C.uchar)(&blind[0]))
	return blinded, blind, rcErr("dia_voprf_blind", rc)
}

// VOPRFEvaluate -> element G1
func VOPRFEvaluate(blinded, sk []byte) (element []byte, err error) {
	ensureInit()
	if len(blinded) != G1Len || len(sk) != FrLen {
		return nil, errors.New("VOPRFEvaluate: bad input sizes")
	}
	element = make([]byte, G1Len)
	rc := C.dia_voprf_evaluate((*C.uchar)(&blinded[0]), (*C.uchar)(&sk[0]),
		(*C.uchar)(&element[0]))
	return element, rcErr("dia_voprf_evaluate", rc)
}

// VOPRFUnblind -> Y G1
func VOPRFUnblind(element, blind []byte) (Y []byte, err error) {
	ensureInit()
	if len(element) != G1Len || len(blind) != FrLen {
		return nil, errors.New("VOPRFUnblind: bad input sizes")
	}
	Y = make([]byte, G1Len)
	rc := C.dia_voprf_unblind((*C.uchar)(&element[0]), (*C.uchar)(&blind[0]),
		(*C.uchar)(&Y[0]))
	return Y, rcErr("dia_voprf_unblind", rc)
}

// VOPRFVerify checks e(H(input), pk) == e(Y, g2).
// Returns (valid, error). error is non-nil only for API/parse failures.
func VOPRFVerify(input, Y, pk []byte) (bool, error) {
	ensureInit()
	if len(Y) != G1Len || len(pk) != G2Len {
		return false, errors.New("VOPRFVerify: bad input sizes")
	}
	var inPtr *C.uchar
	if len(input) > 0 {
		inPtr = (*C.uchar)(unsafe.Pointer(&input[0]))
	}
	var res C.int
	rc := C.dia_voprf_verify(inPtr, C.size_t(len(input)),
		(*C.uchar)(&Y[0]), (*C.uchar)(&pk[0]), &res)
	return res == 1, rcErr("dia_voprf_verify", rc)
}

// VOPRFVerifyBatch verifies N inputs with N outputs Y using 2 pairings.
// Returns (allValid, error).
func VOPRFVerifyBatch(inputs [][]byte, Ys [][]byte, pk []byte) (bool, error) {
	ensureInit()
	if len(pk) != G2Len {
		return false, errors.New("VOPRFVerifyBatch: bad pk size")
	}
	if len(inputs) != len(Ys) {
		return false, errors.New("VOPRFVerifyBatch: len mismatch")
	}
	n := len(inputs)

	// Build C arrays for inputs (pointers + lengths)
	cPtrs := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0))))
	defer C.free(cPtrs)
	cLens := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.size_t(0))))
	defer C.free(cLens)

	ptrs := (*[1 << 30]*C.uchar)(cPtrs)[:n:n]
	lens := (*[1 << 30]C.size_t)(cLens)[:n:n]

	for i := 0; i < n; i++ {
		if len(inputs[i]) == 0 {
			ptrs[i] = nil
			lens[i] = 0
		} else {
			ptrs[i] = (*C.uchar)(unsafe.Pointer(&inputs[i][0]))
			lens[i] = C.size_t(len(inputs[i]))
		}
	}

	// Concatenate Ys into one buffer
	Ycat := make([]byte, n*G1Len)
	for i := 0; i < n; i++ {
		if len(Ys[i]) != G1Len {
			return false, errors.New("VOPRFVerifyBatch: bad Y size")
		}
		copy(Ycat[i*G1Len:(i+1)*G1Len], Ys[i])
	}

	var res C.int
	rc := C.dia_voprf_verify_batch(
		(**C.uchar)(cPtrs),
		(*C.size_t)(cLens),
		C.size_t(n),
		(*C.uchar)(&Ycat[0]),
		(*C.uchar)(&pk[0]),
		&res,
	)
	return res == 1, rcErr("dia_voprf_verify_batch", rc)
}

/* ================================= AMF ================================= */

// AMFKeygen -> (sk Fr, pk G1)
func AMFKeygen() (sk []byte, pk []byte, err error) {
	ensureInit()
	sk = make([]byte, FrLen)
	pk = make([]byte, G1Len)
	rc := C.dia_amf_keygen((*C.uchar)(&sk[0]), (*C.uchar)(&pk[0]))
	return sk, pk, rcErr("dia_amf_keygen", rc)
}

// AMFFrank -> sig blob (opaque)
func AMFFrank(skSender, pkReceiver, pkJudge, msg []byte) (sig []byte, err error) {
	ensureInit()
	if len(skSender) != FrLen || len(pkReceiver) != G1Len || len(pkJudge) != G1Len {
		return nil, errors.New("AMFFrank: bad input sizes")
	}
	var outPtr *C.uchar
	var outLen C.size_t
	var msgPtr *C.uchar
	if len(msg) > 0 {
		msgPtr = (*C.uchar)(unsafe.Pointer(&msg[0]))
	}
	rc := C.dia_amf_frank(
		(*C.uchar)(&skSender[0]),
		(*C.uchar)(&pkReceiver[0]),
		(*C.uchar)(&pkJudge[0]),
		msgPtr, C.size_t(len(msg)),
		(**C.uchar)(unsafe.Pointer(&outPtr)),
		(*C.size_t)(unsafe.Pointer(&outLen)),
	)
	if err = rcErr("dia_amf_frank", rc); err != nil {
		return nil, err
	}
	// Copy out and free C buffer
	sig = C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))
	C.free_byte_buffer(outPtr)
	return sig, nil
}

// AMFVerify (receiver) — checks U==sk_r*B and verifies transcripts.
// Returns (valid, error).
func AMFVerify(pkSender, skReceiver, pkJudge, msg, sig []byte) (bool, error) {
	ensureInit()
	if len(pkSender) != G1Len || len(skReceiver) != FrLen || len(pkJudge) != G1Len {
		return false, errors.New("AMFVerify: bad key sizes")
	}
	var msgPtr *C.uchar
	if len(msg) > 0 {
		msgPtr = (*C.uchar)(unsafe.Pointer(&msg[0]))
	}
	var res C.int
	rc := C.dia_amf_verify(
		(*C.uchar)(&pkSender[0]),
		(*C.uchar)(&skReceiver[0]),
		(*C.uchar)(&pkJudge[0]),
		msgPtr, C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		&res,
	)
	return res == 1, rcErr("dia_amf_verify", rc)
}

// AMFJudge (moderator) — checks T==sk_j*A and verifies transcripts.
// Returns (valid, error).
func AMFJudge(pkSender, pkReceiver, skJudge, msg, sig []byte) (bool, error) {
	ensureInit()
	if len(pkSender) != G1Len || len(pkReceiver) != G1Len || len(skJudge) != FrLen {
		return false, errors.New("AMFJudge: bad key sizes")
	}
	var msgPtr *C.uchar
	if len(msg) > 0 {
		msgPtr = (*C.uchar)(unsafe.Pointer(&msg[0]))
	}
	var res C.int
	rc := C.dia_amf_judge(
		(*C.uchar)(&pkSender[0]),
		(*C.uchar)(&pkReceiver[0]),
		(*C.uchar)(&skJudge[0]),
		msgPtr, C.size_t(len(msg)),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		&res,
	)
	return res == 1, rcErr("dia_amf_judge", rc)
}

/* ================================= BBS ================================= */

// BBSKeygen -> (sk Fr, pk G2)
func BBSKeygen() (sk []byte, pk []byte, err error) {
	ensureInit()
	sk = make([]byte, FrLen)
	pk = make([]byte, G2Len)
	rc := C.dia_bbs_keygen((*C.uchar)(&sk[0]), (*C.uchar)(&pk[0]))
	return sk, pk, rcErr("dia_bbs_keygen", rc)
}

// BBSSign -> opaque signature blob
func BBSSign(msgs [][]byte, sk []byte) (sig []byte, err error) {
	ensureInit()
	if len(sk) != FrLen {
		return nil, errors.New("BBSSign: bad sk size")
	}
	n := len(msgs)

	// Build C arrays for inputs (pointers+lengths)
	cPtrs := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0))))
	defer C.free(cPtrs)
	cLens := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.size_t(0))))
	defer C.free(cLens)

	ptrs := (*[1 << 30]*C.uchar)(cPtrs)[:n:n]
	lens := (*[1 << 30]C.size_t)(cLens)[:n:n]

	for i := 0; i < n; i++ {
		if len(msgs[i]) == 0 {
			ptrs[i] = nil
			lens[i] = 0
		} else {
			ptrs[i] = (*C.uchar)(unsafe.Pointer(&msgs[i][0]))
			lens[i] = C.size_t(len(msgs[i]))
		}
	}

	// Out blob
	var outPtr *C.uchar
	var outLen C.size_t

	rc := C.dia_bbs_sign(
		(**C.uchar)(cPtrs), (*C.size_t)(cLens), C.size_t(n),
		(*C.uchar)(&sk[0]),
		(**C.uchar)(unsafe.Pointer(&outPtr)),
		(*C.size_t)(unsafe.Pointer(&outLen)),
	)
	if err = rcErr("dia_bbs_sign", rc); err != nil {
		return nil, err
	}
	sig = C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))
	C.free_byte_buffer(outPtr)
	return sig, nil
}

// BBSVerify — verify signature over messages with issuer pk.
// Returns (valid, error).
func BBSVerify(msgs [][]byte, pk, sig []byte) (bool, error) {
	ensureInit()
	if len(pk) != G2Len {
		return false, errors.New("BBSVerify: bad pk size")
	}

	n := len(msgs)
	var cPtrs, cLens unsafe.Pointer
	if n > 0 {
		cPtrs = C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0))))
		defer C.free(cPtrs)
		cLens = C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.size_t(0))))
		defer C.free(cLens)

		ptrs := (*[1 << 30]*C.uchar)(cPtrs)[:n:n]
		lens := (*[1 << 30]C.size_t)(cLens)[:n:n]

		for i := 0; i < n; i++ {
			if len(msgs[i]) == 0 {
				ptrs[i] = nil
				lens[i] = 0
			} else {
				ptrs[i] = (*C.uchar)(unsafe.Pointer(&msgs[i][0]))
				lens[i] = C.size_t(len(msgs[i]))
			}
		}
	}

	var res C.int
	rc := C.dia_bbs_verify(
		(**C.uchar)(cPtrs), (*C.size_t)(cLens), C.size_t(n),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		&res,
	)
	return res == 1, rcErr("dia_bbs_verify", rc)
}

// BBSCreateProof → proof blob (opaque) for selective disclosure.
// discloseIdx: 1-based indices of messages to reveal (can be empty).
// Requires issuer pk + opaque signature blob (not (A,e)).
func BBSCreateProof(msgs [][]byte, discloseIdx []uint32,
	pk, sig, nonce []byte) (proof []byte, err error) {

	ensureInit()
	if len(pk) != G2Len {
		return nil, errors.New("BBSCreateProof: bad pk size")
	}

	n := len(msgs)
	cPtrs := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0))))
	defer C.free(cPtrs)
	cLens := C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.size_t(0))))
	defer C.free(cLens)

	ptrs := (*[1 << 30]*C.uchar)(cPtrs)[:n:n]
	lens := (*[1 << 30]C.size_t)(cLens)[:n:n]

	for i := 0; i < n; i++ {
		if len(msgs[i]) == 0 {
			ptrs[i] = nil
			lens[i] = 0
		} else {
			ptrs[i] = (*C.uchar)(unsafe.Pointer(&msgs[i][0]))
			lens[i] = C.size_t(len(msgs[i]))
		}
	}

	// Disclose indices array (can be nil)
	var dPtr *C.uint32_t
	if len(discloseIdx) > 0 {
		dPtr = (*C.uint32_t)(C.malloc(C.size_t(len(discloseIdx)) * C.size_t(unsafe.Sizeof(C.uint32_t(0)))))
		defer C.free(unsafe.Pointer(dPtr))
		dst := (*[1 << 30]C.uint32_t)(unsafe.Pointer(dPtr))[:len(discloseIdx):len(discloseIdx)]
		for i, v := range discloseIdx {
			dst[i] = C.uint32_t(v)
		}
	}

	// Nonce
	var noncePtr *C.uchar
	if len(nonce) > 0 {
		noncePtr = (*C.uchar)(unsafe.Pointer(&nonce[0]))
	}

	// Out blob
	var outPtr *C.uchar
	var outLen C.size_t

	rc := C.dia_bbs_proof_create(
		(**C.uchar)(cPtrs), (*C.size_t)(cLens), C.size_t(n),
		dPtr, C.size_t(len(discloseIdx)),
		(*C.uchar)(&pk[0]),
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		noncePtr, C.size_t(len(nonce)),
		(**C.uchar)(unsafe.Pointer(&outPtr)),
		(*C.size_t)(unsafe.Pointer(&outLen)),
	)
	if err = rcErr("dia_bbs_proof_create", rc); err != nil {
		return nil, err
	}
	proof = C.GoBytes(unsafe.Pointer(outPtr), C.int(outLen))
	C.free_byte_buffer(outPtr)
	return proof, nil
}

// BBSVerifyProof verifies a selective disclosure proof.
// disclosedIdx: 1-based indices of disclosed messages (can be empty)
// disclosedMsgs: must align 1:1 with disclosedIdx (can be empty)
// Returns (valid, error).
func BBSVerifyProof(disclosedIdx []uint32, disclosedMsgs [][]byte,
	pk, nonce, proof []byte) (bool, error) {

	ensureInit()
	if len(pk) != G2Len {
		return false, errors.New("BBSVerifyProof: bad pk size")
	}
	if len(disclosedMsgs) != len(disclosedIdx) {
		return false, errors.New("BBSVerifyProof: index/msg mismatch")
	}
	n := len(disclosedMsgs)

	// C arrays for disclosed messages (pointers+lengths)
	var dPtrs unsafe.Pointer
	var dLens unsafe.Pointer
	if n > 0 {
		dPtrs = C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0))))
		defer C.free(dPtrs)
		dLens = C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(C.size_t(0))))
		defer C.free(dLens)

		ptrs := (*[1 << 30]*C.uchar)(dPtrs)[:n:n]
		lens := (*[1 << 30]C.size_t)(dLens)[:n:n]
		for i := 0; i < n; i++ {
			if len(disclosedMsgs[i]) == 0 {
				ptrs[i] = nil
				lens[i] = 0
			} else {
				ptrs[i] = (*C.uchar)(unsafe.Pointer(&disclosedMsgs[i][0]))
				lens[i] = C.size_t(len(disclosedMsgs[i]))
			}
		}
	}

	// Disclosed indices (can be nil)
	var idxPtr *C.uint32_t
	if len(disclosedIdx) > 0 {
		idxPtr = (*C.uint32_t)(C.malloc(C.size_t(len(disclosedIdx)) * C.size_t(unsafe.Sizeof(C.uint32_t(0)))))
		defer C.free(unsafe.Pointer(idxPtr))
		dst := (*[1 << 30]C.uint32_t)(unsafe.Pointer(idxPtr))[:len(disclosedIdx):len(disclosedIdx)]
		for i, v := range disclosedIdx {
			dst[i] = C.uint32_t(v)
		}
	}

	// Nonce
	var noncePtr *C.uchar
	if len(nonce) > 0 {
		noncePtr = (*C.uchar)(unsafe.Pointer(&nonce[0]))
	}

	var res C.int
	rc := C.dia_bbs_proof_verify(
		idxPtr,
		(**C.uchar)(dPtrs), (*C.size_t)(dLens), C.size_t(n),
		(*C.uchar)(&pk[0]),
		noncePtr, C.size_t(len(nonce)),
		(*C.uchar)(unsafe.Pointer(&proof[0])), C.size_t(len(proof)),
		&res,
	)
	return res == 1, rcErr("dia_bbs_proof_verify", rc)
}
