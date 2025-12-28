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
#define DIA_ERR_VERIFY_FAIL  -3
#define DIA_ERR_ALLOC        -4
#define DIA_ERR_PARSE        -5
#define DIA_ERR_PROTOCOL     -6

/*==============================================================================
 * Message types
 *============================================================================*/
#define DIA_MSG_UNSPECIFIED   0
#define DIA_MSG_AKE_REQUEST   1
#define DIA_MSG_AKE_RESPONSE  2
#define DIA_MSG_AKE_COMPLETE  3
#define DIA_MSG_RUA_REQUEST   4
#define DIA_MSG_RUA_RESPONSE  5
#define DIA_MSG_HEARTBEAT     6
#define DIA_MSG_BYE           7

/*==============================================================================
 * Opaque handles
 *============================================================================*/
typedef struct dia_config_t dia_config_t;
typedef struct dia_callstate_t dia_callstate_t;
typedef struct dia_message_t dia_message_t;

/*==============================================================================
 * Remote party info (returned by dia_callstate_get_remote_party)
 *============================================================================*/
typedef struct dia_remote_party_t {
    char* phone;
    char* name;
    char* logo;
    int   verified;
} dia_remote_party_t;

/*==============================================================================
 * Init / Utilities
 *============================================================================*/

/** Initialize the library. Call once at process start. */
void dia_init(void);

/** Free a heap-allocated string returned by dia_* functions. */
void dia_free_string(char* str);

/** Free a heap-allocated byte buffer returned by dia_* functions. */
void dia_free_bytes(unsigned char* buf);

/** Free a remote party struct (and its string members). */
void dia_free_remote_party(dia_remote_party_t* rp);

/*==============================================================================
 * Config API
 *============================================================================*/

/**
 * Parse a ClientConfig from environment variable format string.
 * Format: KEY=value lines (byte values are hex-encoded).
 * Returns DIA_OK on success, writes to *out.
 */
int dia_config_from_env_string(const char* env_content, dia_config_t** out);

/**
 * Serialize a ClientConfig to environment variable format string.
 * Caller must free returned string with dia_free_string().
 */
int dia_config_to_env_string(const dia_config_t* cfg, char** out);

/** Free a config handle. */
void dia_config_destroy(dia_config_t* cfg);

/*==============================================================================
 * CallState API
 *============================================================================*/

/**
 * Create a new CallState for a call.
 * @param cfg      The client configuration
 * @param phone    The other party's phone number
 * @param outgoing 1 for outgoing (caller), 0 for incoming (recipient)
 * @param out      Output: new CallState handle
 */
int dia_callstate_create(const dia_config_t* cfg,
                         const char* phone,
                         int outgoing,
                         dia_callstate_t** out);

/** Free a CallState handle. */
void dia_callstate_destroy(dia_callstate_t* state);

/** Get the AKE topic (hex string). Caller must free with dia_free_string(). */
int dia_callstate_get_ake_topic(const dia_callstate_t* state, char** out);

/** Get the current active topic (hex string). Caller must free with dia_free_string(). */
int dia_callstate_get_current_topic(const dia_callstate_t* state, char** out);

/** Get the shared key. Caller must free with dia_free_bytes(). */
int dia_callstate_get_shared_key(const dia_callstate_t* state,
                                 unsigned char** out,
                                 size_t* out_len);

/** Get the access ticket. Caller must free with dia_free_bytes(). */
int dia_callstate_get_ticket(const dia_callstate_t* state,
                             unsigned char** out,
                             size_t* out_len);

/** Get the sender ID. Caller must free with dia_free_string(). */
int dia_callstate_get_sender_id(const dia_callstate_t* state, char** out);

/** Returns 1 if caller (outgoing), 0 if recipient. */
int dia_callstate_iam_caller(const dia_callstate_t* state);

/** Returns 1 if recipient (incoming), 0 if caller. */
int dia_callstate_iam_recipient(const dia_callstate_t* state);

/** Returns 1 if RUA phase is active, 0 otherwise. */
int dia_callstate_is_rua_active(const dia_callstate_t* state);

/**
 * Get remote party info (populated after RUA completes).
 * Caller must free with dia_free_remote_party().
 */
int dia_callstate_get_remote_party(const dia_callstate_t* state,
                                   dia_remote_party_t** out);

/** Transition to RUA topic (updates current topic). */
int dia_callstate_transition_to_rua(dia_callstate_t* state);

/*==============================================================================
 * AKE Protocol (Authenticated Key Exchange)
 *============================================================================*/

/** Initialize AKE state (generates DH keys, computes topic). */
int dia_ake_init(dia_callstate_t* state);

/**
 * Caller: Create AkeRequest message.
 * Caller must free output with dia_free_bytes().
 */
int dia_ake_request(dia_callstate_t* state,
                    unsigned char** out,
                    size_t* out_len);

/**
 * Recipient: Process AkeRequest, create AkeResponse.
 * @param state    CallState handle
 * @param msg_data Serialized ProtocolMessage bytes
 * @param msg_len  Length of msg_data
 * @param out      Output: serialized AkeResponse
 * @param out_len  Output: length of response
 */
int dia_ake_response(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len,
                     unsigned char** out,
                     size_t* out_len);

/**
 * Caller: Process AkeResponse, create AkeComplete.
 * After this, shared key is computed.
 */
int dia_ake_complete(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len,
                     unsigned char** out,
                     size_t* out_len);

/**
 * Recipient: Process AkeComplete, finalize AKE.
 * After this, shared key is computed.
 */
int dia_ake_finalize(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len);

/*==============================================================================
 * RUA Protocol (Rich User Authentication)
 *============================================================================*/

/**
 * Derive RUA topic from shared key.
 * Caller must free output with dia_free_string().
 */
int dia_rua_derive_topic(const dia_callstate_t* state, char** out);

/** Initialize RTU for RUA phase. */
int dia_rua_init(dia_callstate_t* state);

/**
 * Caller: Create RuaRequest message.
 * Caller must free output with dia_free_bytes().
 */
int dia_rua_request(dia_callstate_t* state,
                    unsigned char** out,
                    size_t* out_len);

/**
 * Recipient: Process RuaRequest, create RuaResponse.
 * After this, new shared key is computed and remote_party is populated.
 */
int dia_rua_response(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len,
                     unsigned char** out,
                     size_t* out_len);

/**
 * Caller: Process RuaResponse, finalize RUA.
 * After this, new shared key is computed and remote_party is populated.
 */
int dia_rua_finalize(dia_callstate_t* state,
                     const unsigned char* msg_data,
                     size_t msg_len);

/*==============================================================================
 * Message Handling
 *============================================================================*/

/**
 * Deserialize a ProtocolMessage from bytes.
 * Caller must free with dia_message_destroy().
 */
int dia_message_deserialize(const unsigned char* data,
                            size_t len,
                            dia_message_t** out);

/** Free a message handle. */
void dia_message_destroy(dia_message_t* msg);

/** Get the message type (DIA_MSG_* constant). */
int dia_message_get_type(const dia_message_t* msg);

/** Get sender ID. Caller must free with dia_free_string(). */
int dia_message_get_sender_id(const dia_message_t* msg, char** out);

/** Get topic. Caller must free with dia_free_string(). */
int dia_message_get_topic(const dia_message_t* msg, char** out);

/**
 * Create a Bye message.
 * Caller must free output with dia_free_bytes().
 */
int dia_message_create_bye(const dia_callstate_t* state,
                           unsigned char** out,
                           size_t* out_len);

/**
 * Create a Heartbeat message.
 * Caller must free output with dia_free_bytes().
 */
int dia_message_create_heartbeat(const dia_callstate_t* state,
                                 unsigned char** out,
                                 size_t* out_len);

/*==============================================================================
 * DR Messaging (post-RUA secure messaging)
 *============================================================================*/

/**
 * Encrypt a message using the Double Ratchet session.
 * Caller must free output with dia_free_bytes().
 */
int dia_dr_encrypt(dia_callstate_t* state,
                   const unsigned char* plaintext,
                   size_t plaintext_len,
                   unsigned char** out,
                   size_t* out_len);

/**
 * Decrypt a message using the Double Ratchet session.
 * Caller must free output with dia_free_bytes().
 */
int dia_dr_decrypt(dia_callstate_t* state,
                   const unsigned char* ciphertext,
                   size_t ciphertext_len,
                   unsigned char** out,
                   size_t* out_len);

#ifdef __cplusplus
}
#endif

#endif /* DIA_C_H */
