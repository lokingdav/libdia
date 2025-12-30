package io.github.lokingdav.libdia

/**
 * LibDia - Dynamic Identity Authentication library for Android
 *
 * This library provides the DIA Protocol implementation for:
 * - Authenticated Key Exchange (AKE)
 * - Right-To-Use Authentication (RUA)
 * - Double Ratchet secure messaging (DR)
 * - Enrollment and credential management
 */
object LibDia {
    init { System.loadLibrary("dia_jni") }

    // ===================== Config =====================
    /** Parse a Config from environment variable format string. Returns native handle. */
    external fun configFromEnv(envContent: String): Long

    /** Serialize a Config to environment variable format string. */
    external fun configToEnv(handle: Long): String

    /** Free a Config handle. */
    external fun configDestroy(handle: Long)

    // ===================== CallState =====================
    /** Create a new CallState for a call. Returns native handle. */
    external fun callStateCreate(configHandle: Long, phone: String, outgoing: Boolean): Long

    /** Free a CallState handle. */
    external fun callStateDestroy(handle: Long)

    /** Get the AKE topic (hex string). */
    external fun callStateGetAkeTopic(handle: Long): String

    /** Get the current active topic (hex string). */
    external fun callStateGetCurrentTopic(handle: Long): String

    /** Get the shared key (available after AKE completes). */
    external fun callStateGetSharedKey(handle: Long): ByteArray

    /** Get the access ticket. */
    external fun callStateGetTicket(handle: Long): ByteArray

    /** Get the sender ID. */
    external fun callStateGetSenderId(handle: Long): String

    /** Returns true if this is an outgoing call (we are the caller). */
    external fun callStateIsCaller(handle: Long): Boolean

    /** Returns true if this is an incoming call (we are the recipient). */
    external fun callStateIsRecipient(handle: Long): Boolean

    /** Returns true if the RUA phase is active. */
    external fun callStateIsRuaActive(handle: Long): Boolean

    /** Get remote party info as [phone, name, logo, verified]. Populated after RUA. */
    external fun callStateGetRemoteParty(handle: Long): Array<String>

    /** Transition to RUA topic (updates current topic). */
    external fun callStateTransitionToRua(handle: Long)

    // ===================== AKE Protocol =====================
    /** Initialize AKE state (generates DH keys, computes topic). */
    external fun akeInit(callStateHandle: Long)

    /** Caller: Create AKE request message. */
    external fun akeRequest(callStateHandle: Long): ByteArray

    /** Recipient: Process AKE request, create AKE response. */
    external fun akeResponse(callStateHandle: Long, msgData: ByteArray): ByteArray

    /** Caller: Process AKE response, create AKE complete message. */
    external fun akeComplete(callStateHandle: Long, msgData: ByteArray): ByteArray

    /** Recipient: Process AKE complete, finalize AKE. */
    external fun akeFinalize(callStateHandle: Long, msgData: ByteArray)

    // ===================== RUA Protocol =====================
    /** Derive RUA topic from shared key. */
    external fun ruaDeriveTopic(callStateHandle: Long): String

    /** Initialize RTU for RUA phase. */
    external fun ruaInit(callStateHandle: Long)

    /** Caller: Create RUA request message. */
    external fun ruaRequest(callStateHandle: Long): ByteArray

    /** Recipient: Process RUA request, create RUA response. */
    external fun ruaResponse(callStateHandle: Long, msgData: ByteArray): ByteArray

    /** Caller: Process RUA response, finalize RUA. */
    external fun ruaFinalize(callStateHandle: Long, msgData: ByteArray)

    // ===================== Messages =====================
    /** Deserialize a protocol message. Returns native handle. */
    external fun messageDeserialize(data: ByteArray): Long

    /** Free a message handle. */
    external fun messageDestroy(handle: Long)

    /** Get message type (MSG_* constant). */
    external fun messageGetType(handle: Long): Int

    /** Get sender ID from message. */
    external fun messageGetSenderId(handle: Long): String

    /** Get topic from message. */
    external fun messageGetTopic(handle: Long): String

    /** Create a Bye message. */
    external fun messageCreateBye(callStateHandle: Long): ByteArray

    /** Create a Heartbeat message. */
    external fun messageCreateHeartbeat(callStateHandle: Long): ByteArray

    // ===================== DR Messaging =====================
    /** Encrypt a message using Double Ratchet. */
    external fun drEncrypt(callStateHandle: Long, plaintext: ByteArray): ByteArray

    /** Decrypt a message using Double Ratchet. */
    external fun drDecrypt(callStateHandle: Long, ciphertext: ByteArray): ByteArray

    // ===================== Enrollment =====================
    /**
     * Create an enrollment request.
     * Returns [[keysHandle (8 bytes)], [request bytes]]
     */
    external fun enrollmentCreateRequest(
        phone: String,
        name: String,
        logoUrl: String?,
        numTickets: Int
    ): Array<ByteArray>

    /**
     * Finalize enrollment after receiving server response.
     * Returns config handle.
     */
    external fun enrollmentFinalize(
        keysHandle: ByteArray,
        response: ByteArray,
        phone: String,
        name: String,
        logoUrl: String?
    ): Long

    /** Free enrollment keys handle. */
    external fun enrollmentKeysDestroy(keysHandle: ByteArray)

    // ===================== Ticket Verification =====================
    /** Verify a ticket using the VOPRF verification key. */
    external fun verifyTicket(ticket: ByteArray, verifyKey: ByteArray): Boolean

    // ===================== Message Type Constants =====================
    companion object {
        const val MSG_UNSPECIFIED = 0
        const val MSG_AKE_REQUEST = 1
        const val MSG_AKE_RESPONSE = 2
        const val MSG_AKE_COMPLETE = 3
        const val MSG_RUA_REQUEST = 4
        const val MSG_RUA_RESPONSE = 5
        const val MSG_HEARTBEAT = 6
        const val MSG_BYE = 7
    }
}
