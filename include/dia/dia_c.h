#ifndef DIA_C_H
#define DIA_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*==============================================================================
 * Status codes
 *============================================================================*/
#define DIA_OK                0
#define DIA_ERR              -1
#define DIA_ERR_INVALID_ARG  -2
#define DIA_ERR_VERIFY_FAIL  -3  /* (kept for ABI compatibility; no longer returned by *_verify) */
#define DIA_ERR_ALLOC        -4

/*==============================================================================
 * Fixed sizes (BN256 / MCL defaults; compressed encodings)
 *============================================================================*/
#define DIA_FR_LEN   32   /* Scalar size */
#define DIA_G1_LEN   32   /* G1 compressed */
#define DIA_G2_LEN   64   /* G2 compressed */
#define DIA_GT_LEN   384  /* GT serialized (not usually needed at FFI) */

/*==============================================================================
 * Init / Utilities
 *============================================================================*/

/** Initialize the underlying pairing library (MCL). Call once at process start. */
void init_dia(void);

/** Free a heap buffer previously returned by any dia_* function. */
void free_byte_buffer(unsigned char* buf);

/*==============================================================================
 * Diffie-hellman (PK in G1)
 *============================================================================*/
/** Generate server key pair: sk (Fr), pk (G1). */
int dia_dh_keygen(/*out*/ unsigned char sk[DIA_FR_LEN],
                     /*out*/ unsigned char pk[DIA_G1_LEN]);

/** Server: evaluate on a blinded element using sk. */
int dia_dh_compute_secret(const unsigned char a[DIA_FR_LEN],
                       const unsigned char B[DIA_G1_LEN],
                       /*out*/ unsigned char out_element[DIA_G1_LEN]);

/*==============================================================================
 * VOPRF (server PK in G2, outputs in G1)
 *  - Inputs are raw byte strings; hashing is done internally.
 *============================================================================*/

/** Generate server key pair: sk (Fr), pk (G2). */
int dia_voprf_keygen(/*out*/ unsigned char sk[DIA_FR_LEN],
                     /*out*/ unsigned char pk[DIA_G2_LEN]);

/** Client: blind an input. Returns the blinded element (G1) and the blind (Fr). */
int dia_voprf_blind(const unsigned char* input, size_t input_len,
                    /*out*/ unsigned char out_blinded[DIA_G1_LEN],
                    /*out*/ unsigned char out_blind[DIA_FR_LEN]);

/** Server: evaluate on a blinded element using sk. */
int dia_voprf_evaluate(const unsigned char blinded[DIA_G1_LEN],
                       const unsigned char sk[DIA_FR_LEN],
                       /*out*/ unsigned char out_element[DIA_G1_LEN]);

/** Client: unblind server element using the blind to obtain final output Y (G1). */
int dia_voprf_unblind(const unsigned char element[DIA_G1_LEN],
                      const unsigned char blind[DIA_FR_LEN],
                      /*out*/ unsigned char out_Y[DIA_G1_LEN]);

/**
 * Verify a single OPRF output Y against input and server pk.
 * Returns DIA_OK and sets *result to 1 (valid) or 0 (invalid).
 */
int dia_voprf_verify(const unsigned char* input, size_t input_len,
                     const unsigned char Y[DIA_G1_LEN],
                     const unsigned char pk[DIA_G2_LEN],
                     /*out*/ int* result);

/**
 * Verify a batch of OPRF outputs in one shot (2 pairings).
 * inputs:      array of pointers to input buffers
 * input_lens:  array of lengths (same length as inputs)
 * n:           number of items
 * Y_concat:    n concatenated G1 elements (n * DIA_G1_LEN bytes)
 * Returns DIA_OK and sets *result to 1 (all valid) or 0 (invalid).
 */
int dia_voprf_verify_batch(const unsigned char* const* inputs,
                           const size_t* input_lens,
                           size_t n,
                           const unsigned char* Y_concat,
                           const unsigned char pk[DIA_G2_LEN],
                           /*out*/ int* result);

/*==============================================================================
 * AMF (Asymmetric Message Franking)
 *  - All keys live in G1 (pk = sk * g1), secrets are Fr.
 *  - Signatures are returned as an opaque byte blob; use free_byte_buffer().
 *============================================================================*/

/** Key generation for any AMF role (sender/receiver/judge): sk (Fr), pk (G1). */
int dia_amf_keygen(/*out*/ unsigned char sk[DIA_FR_LEN],
                   /*out*/ unsigned char pk[DIA_G1_LEN]);

/**
 * Frank (sender): produce an AMF signature over a message for receiver+judge keys.
 * Returns an opaque signature blob (allocated); caller must free with free_byte_buffer().
 */
int dia_amf_frank(const unsigned char sk_sender[DIA_FR_LEN],
                  const unsigned char pk_receiver[DIA_G1_LEN],
                  const unsigned char pk_judge[DIA_G1_LEN],
                  const unsigned char* msg, size_t msg_len,
                  /*out*/ unsigned char** sig_blob,
                  /*out*/ size_t* sig_blob_len);

/**
 * Verify (receiver): check signature validity and that it is bound to receiver’s sk.
 * Returns DIA_OK and sets *result to 1 (valid) or 0 (invalid).
 */
int dia_amf_verify(const unsigned char pk_sender[DIA_G1_LEN],
                   const unsigned char sk_receiver[DIA_FR_LEN],
                   const unsigned char pk_judge[DIA_G1_LEN],
                   const unsigned char* msg, size_t msg_len,
                   const unsigned char* sig_blob, size_t sig_blob_len,
                   /*out*/ int* result);

/**
 * Judge (moderator): verify signature and that it is bound to judge’s sk.
 * Returns DIA_OK and sets *result to 1 (valid) or 0 (invalid).
 */
int dia_amf_judge(const unsigned char pk_sender[DIA_G1_LEN],
                  const unsigned char pk_receiver[DIA_G1_LEN],
                  const unsigned char sk_judge[DIA_FR_LEN],
                  const unsigned char* msg, size_t msg_len,
                  const unsigned char* sig_blob, size_t sig_blob_len,
                  /*out*/ int* result);

/*==============================================================================
 * BBS (compact signature) + Selective Disclosure (GT-based)
 *  - Issuer pk in G2 (pk = g2^sk), secret is Fr.
 *  - Messages are raw byte strings; hashed to Scalars internally.
 *  - Signatures and proofs are **opaque byte blobs** (allocated).
 *============================================================================*/

/** BBS key generation: sk (Fr), pk (G2). */
int dia_bbs_keygen(/*out*/ unsigned char sk[DIA_FR_LEN],
                   /*out*/ unsigned char pk[DIA_G2_LEN]);

/**
 * BBS sign over a list of messages (hashed internally).
 * Output: signature blob `sig_blob` (allocated; free with free_byte_buffer()).
 */
int dia_bbs_sign(const unsigned char* const* msgs,
                 const size_t* msg_lens,
                 size_t n_msgs,
                 const unsigned char sk[DIA_FR_LEN],
                 /*out*/ unsigned char** sig_blob,
                 /*out*/ size_t* sig_blob_len);

/** Verify a BBS signature (messages are hashed internally).
 *  Returns DIA_OK and sets *result to 1 (valid) or 0 (invalid).
 */
int dia_bbs_verify(const unsigned char* const* msgs,
                   const size_t* msg_lens,
                   size_t n_msgs,
                   const unsigned char pk[DIA_G2_LEN],
                   const unsigned char* sig_blob,
                   size_t sig_blob_len,
                   /*out*/ int* result);

/**
 * Create a selective-disclosure proof (GT-based working variant).
 * Output: proof_blob (allocated opaque), proof_blob_len.
 */
int dia_bbs_proof_create(const unsigned char* const* msgs,
                         const size_t* msg_lens,
                         size_t n_msgs,
                         const uint32_t* disclose_idx_1based,
                         size_t n_disclose,
                         const unsigned char pk[DIA_G2_LEN],
                         const unsigned char* sig_blob,
                         size_t sig_blob_len,
                         const unsigned char* nonce,
                         size_t nonce_len,
                         /*out*/ unsigned char** proof_blob,
                         /*out*/ size_t* proof_blob_len);

/**
 * Verify a selective-disclosure proof.
 * Returns DIA_OK and sets *result to 1 (valid) or 0 (invalid).
 */
int dia_bbs_proof_verify(const uint32_t* disclosed_idx_1based,
                         const unsigned char* const* disclosed_msgs,
                         const size_t* disclosed_lens,
                         size_t n_disclosed,
                         const unsigned char pk[DIA_G2_LEN],
                         const unsigned char* nonce,
                         size_t nonce_len,
                         const unsigned char* proof_blob,
                         size_t proof_blob_len,
                         /*out*/ int* result);

#ifdef __cplusplus
}
#endif

#endif /* DIA_C_H */
