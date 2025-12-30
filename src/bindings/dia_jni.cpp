// dia_jni.cpp
// JNI bindings for DIA Protocol - matches the C interface (dia_c.h)
#include <jni.h>
#include <string>
#include <vector>
#include <cstring>

#include <dia/dia_c.h>

// Target Java/Kotlin class
#define DIA_JNI_CLASS "io/github/lokingdav/libdia/LibDia"

/* ============================= Small Helpers ============================== */

static void throwIllegalArg(JNIEnv* env, const char* msg) {
    jclass ex = env->FindClass("java/lang/IllegalArgumentException");
    if (!ex) ex = env->FindClass("java/lang/RuntimeException");
    env->ThrowNew(ex, msg ? msg : "IllegalArgumentException");
}

static void throwRuntime(JNIEnv* env, const std::string& msg) {
    jclass ex = env->FindClass("java/lang/RuntimeException");
    if (!ex) return;
    env->ThrowNew(ex, msg.c_str());
}

static std::vector<unsigned char> getBytes(JNIEnv* env, jbyteArray arr) {
    std::vector<unsigned char> out;
    if (!arr) return out;
    const jsize n = env->GetArrayLength(arr);
    out.resize(static_cast<size_t>(n));
    if (n > 0) {
        env->GetByteArrayRegion(arr, 0, n, reinterpret_cast<jbyte*>(out.data()));
    }
    return out;
}

static jbyteArray makeByteArray(JNIEnv* env, const unsigned char* data, size_t len) {
    jbyteArray arr = env->NewByteArray(static_cast<jsize>(len));
    if (!arr) return nullptr;
    if (len) {
        env->SetByteArrayRegion(arr, 0, static_cast<jsize>(len),
                                reinterpret_cast<const jbyte*>(data));
    }
    return arr;
}

static jobjectArray make2DByteArray(JNIEnv* env, jsize outerLen) {
    jclass baClass = env->FindClass("[B");
    return env->NewObjectArray(outerLen, baClass, nullptr);
}

static void set2DByteArrayElem(JNIEnv* env, jobjectArray arr, jsize idx,
                               const unsigned char* p, size_t n) {
    jbyteArray inner = makeByteArray(env, p, n);
    env->SetObjectArrayElement(arr, idx, inner);
    env->DeleteLocalRef(inner);
}

static bool rcIsOk(JNIEnv* env, const char* op, int rc) {
    if (rc == DIA_OK) return true;
    throwRuntime(env, std::string(op) + " failed: rc=" + std::to_string(rc));
    return false;
}

/* ========================== Config API ==================================== */

static jlong native_configFromEnv(JNIEnv* env, jclass, jstring jEnvContent) {
    if (!jEnvContent) {
        throwIllegalArg(env, "envContent is null");
        return 0;
    }
    const char* envContent = env->GetStringUTFChars(jEnvContent, nullptr);
    if (!envContent) return 0;

    dia_config_t* cfg = nullptr;
    int rc = dia_config_from_env_string(envContent, &cfg);
    env->ReleaseStringUTFChars(jEnvContent, envContent);

    if (!rcIsOk(env, "dia_config_from_env_string", rc)) return 0;
    return reinterpret_cast<jlong>(cfg);
}

static jstring native_configToEnv(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "config handle is null");
        return nullptr;
    }
    auto cfg = reinterpret_cast<dia_config_t*>(handle);

    char* envStr = nullptr;
    if (!rcIsOk(env, "dia_config_to_env_string", dia_config_to_env_string(cfg, &envStr))) {
        return nullptr;
    }
    jstring result = env->NewStringUTF(envStr);
    dia_free_string(envStr);
    return result;
}

static void native_configDestroy(JNIEnv*, jclass, jlong handle) {
    if (handle) {
        dia_config_destroy(reinterpret_cast<dia_config_t*>(handle));
    }
}

/* ========================== CallState API ================================= */

static jlong native_callStateCreate(JNIEnv* env, jclass, jlong configHandle, jstring jPhone, jboolean outgoing) {
    if (!configHandle) {
        throwIllegalArg(env, "config handle is null");
        return 0;
    }
    if (!jPhone) {
        throwIllegalArg(env, "phone is null");
        return 0;
    }
    auto cfg = reinterpret_cast<dia_config_t*>(configHandle);
    const char* phone = env->GetStringUTFChars(jPhone, nullptr);
    if (!phone) return 0;

    dia_callstate_t* state = nullptr;
    int rc = dia_callstate_create(cfg, phone, outgoing ? 1 : 0, &state);
    env->ReleaseStringUTFChars(jPhone, phone);

    if (!rcIsOk(env, "dia_callstate_create", rc)) return 0;
    return reinterpret_cast<jlong>(state);
}

static void native_callStateDestroy(JNIEnv*, jclass, jlong handle) {
    if (handle) {
        dia_callstate_destroy(reinterpret_cast<dia_callstate_t*>(handle));
    }
}

static jstring native_callStateGetAkeTopic(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    char* topic = nullptr;
    if (!rcIsOk(env, "dia_callstate_get_ake_topic", dia_callstate_get_ake_topic(state, &topic))) {
        return nullptr;
    }
    jstring result = env->NewStringUTF(topic);
    dia_free_string(topic);
    return result;
}

static jstring native_callStateGetCurrentTopic(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    char* topic = nullptr;
    if (!rcIsOk(env, "dia_callstate_get_current_topic", dia_callstate_get_current_topic(state, &topic))) {
        return nullptr;
    }
    jstring result = env->NewStringUTF(topic);
    dia_free_string(topic);
    return result;
}

static jbyteArray native_callStateGetSharedKey(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    unsigned char* key = nullptr;
    size_t keyLen = 0;
    if (!rcIsOk(env, "dia_callstate_get_shared_key", dia_callstate_get_shared_key(state, &key, &keyLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, key, keyLen);
    dia_free_bytes(key);
    return result;
}

static jbyteArray native_callStateGetTicket(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    unsigned char* ticket = nullptr;
    size_t ticketLen = 0;
    if (!rcIsOk(env, "dia_callstate_get_ticket", dia_callstate_get_ticket(state, &ticket, &ticketLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, ticket, ticketLen);
    dia_free_bytes(ticket);
    return result;
}

static jstring native_callStateGetSenderId(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    char* senderId = nullptr;
    if (!rcIsOk(env, "dia_callstate_get_sender_id", dia_callstate_get_sender_id(state, &senderId))) {
        return nullptr;
    }
    jstring result = env->NewStringUTF(senderId);
    dia_free_string(senderId);
    return result;
}

static jboolean native_callStateIsCaller(JNIEnv*, jclass, jlong handle) {
    if (!handle) return JNI_FALSE;
    return dia_callstate_iam_caller(reinterpret_cast<dia_callstate_t*>(handle)) ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_callStateIsRecipient(JNIEnv*, jclass, jlong handle) {
    if (!handle) return JNI_FALSE;
    return dia_callstate_iam_recipient(reinterpret_cast<dia_callstate_t*>(handle)) ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_callStateIsRuaActive(JNIEnv*, jclass, jlong handle) {
    if (!handle) return JNI_FALSE;
    return dia_callstate_is_rua_active(reinterpret_cast<dia_callstate_t*>(handle)) ? JNI_TRUE : JNI_FALSE;
}

static jobjectArray native_callStateGetRemoteParty(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    dia_remote_party_t* rp = nullptr;
    if (!rcIsOk(env, "dia_callstate_get_remote_party", dia_callstate_get_remote_party(state, &rp))) {
        return nullptr;
    }

    // Return as String[4]: [phone, name, logo, verified ("true"/"false")]
    jclass strClass = env->FindClass("java/lang/String");
    jobjectArray result = env->NewObjectArray(4, strClass, nullptr);
    env->SetObjectArrayElement(result, 0, env->NewStringUTF(rp->phone ? rp->phone : ""));
    env->SetObjectArrayElement(result, 1, env->NewStringUTF(rp->name ? rp->name : ""));
    env->SetObjectArrayElement(result, 2, env->NewStringUTF(rp->logo ? rp->logo : ""));
    env->SetObjectArrayElement(result, 3, env->NewStringUTF(rp->verified ? "true" : "false"));

    dia_free_remote_party(rp);
    return result;
}

static void native_callStateTransitionToRua(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    rcIsOk(env, "dia_callstate_transition_to_rua", dia_callstate_transition_to_rua(state));
}

/* ========================== AKE Protocol ================================== */

static void native_akeInit(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    rcIsOk(env, "dia_ake_init", dia_ake_init(state));
}

static jbyteArray native_akeRequest(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_ake_request", dia_ake_request(state, &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

static jbyteArray native_akeResponse(JNIEnv* env, jclass, jlong handle, jbyteArray jMsgData) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    auto msgData = getBytes(env, jMsgData);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_ake_response", dia_ake_response(state, msgData.data(), msgData.size(), &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

static jbyteArray native_akeComplete(JNIEnv* env, jclass, jlong handle, jbyteArray jMsgData) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    auto msgData = getBytes(env, jMsgData);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_ake_complete", dia_ake_complete(state, msgData.data(), msgData.size(), &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

static void native_akeFinalize(JNIEnv* env, jclass, jlong handle, jbyteArray jMsgData) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    auto msgData = getBytes(env, jMsgData);
    rcIsOk(env, "dia_ake_finalize", dia_ake_finalize(state, msgData.data(), msgData.size()));
}

/* ========================== RUA Protocol ================================== */

static jstring native_ruaDeriveTopic(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    char* topic = nullptr;
    if (!rcIsOk(env, "dia_rua_derive_topic", dia_rua_derive_topic(state, &topic))) {
        return nullptr;
    }
    jstring result = env->NewStringUTF(topic);
    dia_free_string(topic);
    return result;
}

static void native_ruaInit(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    rcIsOk(env, "dia_rua_init", dia_rua_init(state));
}

static jbyteArray native_ruaRequest(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_rua_request", dia_rua_request(state, &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

static jbyteArray native_ruaResponse(JNIEnv* env, jclass, jlong handle, jbyteArray jMsgData) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    auto msgData = getBytes(env, jMsgData);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_rua_response", dia_rua_response(state, msgData.data(), msgData.size(), &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

static void native_ruaFinalize(JNIEnv* env, jclass, jlong handle, jbyteArray jMsgData) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    auto msgData = getBytes(env, jMsgData);
    rcIsOk(env, "dia_rua_finalize", dia_rua_finalize(state, msgData.data(), msgData.size()));
}

/* ========================== Message API =================================== */

static jlong native_messageDeserialize(JNIEnv* env, jclass, jbyteArray jData) {
    auto data = getBytes(env, jData);
    if (data.empty()) {
        throwIllegalArg(env, "data is empty");
        return 0;
    }

    dia_message_t* msg = nullptr;
    if (!rcIsOk(env, "dia_message_deserialize", dia_message_deserialize(data.data(), data.size(), &msg))) {
        return 0;
    }
    return reinterpret_cast<jlong>(msg);
}

static void native_messageDestroy(JNIEnv*, jclass, jlong handle) {
    if (handle) {
        dia_message_destroy(reinterpret_cast<dia_message_t*>(handle));
    }
}

static jint native_messageGetType(JNIEnv*, jclass, jlong handle) {
    if (!handle) return 0;
    return dia_message_get_type(reinterpret_cast<dia_message_t*>(handle));
}

static jstring native_messageGetSenderId(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "message handle is null");
        return nullptr;
    }
    auto msg = reinterpret_cast<dia_message_t*>(handle);

    char* senderId = nullptr;
    if (!rcIsOk(env, "dia_message_get_sender_id", dia_message_get_sender_id(msg, &senderId))) {
        return nullptr;
    }
    jstring result = env->NewStringUTF(senderId);
    dia_free_string(senderId);
    return result;
}

static jstring native_messageGetTopic(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "message handle is null");
        return nullptr;
    }
    auto msg = reinterpret_cast<dia_message_t*>(handle);

    char* topic = nullptr;
    if (!rcIsOk(env, "dia_message_get_topic", dia_message_get_topic(msg, &topic))) {
        return nullptr;
    }
    jstring result = env->NewStringUTF(topic);
    dia_free_string(topic);
    return result;
}

static jbyteArray native_messageCreateBye(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_message_create_bye", dia_message_create_bye(state, &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

static jbyteArray native_messageCreateHeartbeat(JNIEnv* env, jclass, jlong handle) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_message_create_heartbeat", dia_message_create_heartbeat(state, &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

/* ========================== DR Messaging ================================== */

static jbyteArray native_drEncrypt(JNIEnv* env, jclass, jlong handle, jbyteArray jPlaintext) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    auto plaintext = getBytes(env, jPlaintext);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_dr_encrypt", dia_dr_encrypt(state, plaintext.data(), plaintext.size(), &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

static jbyteArray native_drDecrypt(JNIEnv* env, jclass, jlong handle, jbyteArray jCiphertext) {
    if (!handle) {
        throwIllegalArg(env, "callstate handle is null");
        return nullptr;
    }
    auto state = reinterpret_cast<dia_callstate_t*>(handle);
    auto ciphertext = getBytes(env, jCiphertext);

    unsigned char* out = nullptr;
    size_t outLen = 0;
    if (!rcIsOk(env, "dia_dr_decrypt", dia_dr_decrypt(state, ciphertext.data(), ciphertext.size(), &out, &outLen))) {
        return nullptr;
    }
    jbyteArray result = makeByteArray(env, out, outLen);
    dia_free_bytes(out);
    return result;
}

/* ========================== Enrollment ==================================== */

static jobjectArray native_enrollmentCreateRequest(JNIEnv* env, jclass,
                                                   jstring jPhone, jstring jName,
                                                   jstring jLogoUrl, jint numTickets) {
    if (!jPhone || !jName) {
        throwIllegalArg(env, "phone and name are required");
        return nullptr;
    }

    const char* phone = env->GetStringUTFChars(jPhone, nullptr);
    const char* name = env->GetStringUTFChars(jName, nullptr);
    const char* logoUrl = jLogoUrl ? env->GetStringUTFChars(jLogoUrl, nullptr) : "";

    dia_enrollment_keys_t* keys = nullptr;
    unsigned char* request = nullptr;
    size_t requestLen = 0;

    int rc = dia_enrollment_create_request(phone, name, logoUrl, static_cast<size_t>(numTickets),
                                           &keys, &request, &requestLen);

    env->ReleaseStringUTFChars(jPhone, phone);
    env->ReleaseStringUTFChars(jName, name);
    if (jLogoUrl) env->ReleaseStringUTFChars(jLogoUrl, logoUrl);

    if (!rcIsOk(env, "dia_enrollment_create_request", rc)) return nullptr;

    // Return [[keysHandle as 8-byte long], [request bytes]]
    jobjectArray result = make2DByteArray(env, 2);

    // Store keys handle as 8 bytes (little-endian long)
    jlong keysHandle = reinterpret_cast<jlong>(keys);
    unsigned char handleBytes[8];
    for (int i = 0; i < 8; i++) {
        handleBytes[i] = static_cast<unsigned char>((keysHandle >> (i * 8)) & 0xFF);
    }
    set2DByteArrayElem(env, result, 0, handleBytes, 8);
    set2DByteArrayElem(env, result, 1, request, requestLen);

    dia_free_bytes(request);
    return result;
}

static jlong native_enrollmentFinalize(JNIEnv* env, jclass,
                                       jbyteArray jKeysHandle, jbyteArray jResponse,
                                       jstring jPhone, jstring jName, jstring jLogoUrl) {
    if (!jKeysHandle || !jResponse || !jPhone || !jName) {
        throwIllegalArg(env, "keysHandle, response, phone, and name are required");
        return 0;
    }

    // Extract keys handle from 8-byte array
    auto handleBytes = getBytes(env, jKeysHandle);
    if (handleBytes.size() != 8) {
        throwIllegalArg(env, "keysHandle must be 8 bytes");
        return 0;
    }
    jlong keysHandle = 0;
    for (int i = 0; i < 8; i++) {
        keysHandle |= (static_cast<jlong>(handleBytes[i]) << (i * 8));
    }
    auto keys = reinterpret_cast<dia_enrollment_keys_t*>(keysHandle);

    auto response = getBytes(env, jResponse);
    const char* phone = env->GetStringUTFChars(jPhone, nullptr);
    const char* name = env->GetStringUTFChars(jName, nullptr);
    const char* logoUrl = jLogoUrl ? env->GetStringUTFChars(jLogoUrl, nullptr) : "";

    dia_config_t* config = nullptr;
    int rc = dia_enrollment_finalize(keys, response.data(), response.size(),
                                     phone, name, logoUrl, &config);

    env->ReleaseStringUTFChars(jPhone, phone);
    env->ReleaseStringUTFChars(jName, name);
    if (jLogoUrl) env->ReleaseStringUTFChars(jLogoUrl, logoUrl);

    if (!rcIsOk(env, "dia_enrollment_finalize", rc)) return 0;
    return reinterpret_cast<jlong>(config);
}

static void native_enrollmentKeysDestroy(JNIEnv* env, jclass, jbyteArray jKeysHandle) {
    if (!jKeysHandle) return;

    auto handleBytes = getBytes(env, jKeysHandle);
    if (handleBytes.size() != 8) return;

    jlong keysHandle = 0;
    for (int i = 0; i < 8; i++) {
        keysHandle |= (static_cast<jlong>(handleBytes[i]) << (i * 8));
    }
    if (keysHandle) {
        dia_enrollment_keys_destroy(reinterpret_cast<dia_enrollment_keys_t*>(keysHandle));
    }
}

/* ========================== Ticket Verification =========================== */

static jboolean native_verifyTicket(JNIEnv* env, jclass, jbyteArray jTicket, jbyteArray jVerifyKey) {
    auto ticket = getBytes(env, jTicket);
    auto verifyKey = getBytes(env, jVerifyKey);

    if (ticket.empty() || verifyKey.empty()) {
        throwIllegalArg(env, "ticket and verifyKey are required");
        return JNI_FALSE;
    }

    int result = dia_verify_ticket(ticket.data(), ticket.size(), verifyKey.data(), verifyKey.size());
    if (result < 0) {
        rcIsOk(env, "dia_verify_ticket", result);
        return JNI_FALSE;
    }
    return result == 1 ? JNI_TRUE : JNI_FALSE;
}

/* ============================ Registration =============================== */

static JNINativeMethod gMethods[] = {
    // Config
    { "configFromEnv",    "(Ljava/lang/String;)J",          (void*)native_configFromEnv },
    { "configToEnv",      "(J)Ljava/lang/String;",          (void*)native_configToEnv },
    { "configDestroy",    "(J)V",                           (void*)native_configDestroy },

    // CallState
    { "callStateCreate",           "(JLjava/lang/String;Z)J",  (void*)native_callStateCreate },
    { "callStateDestroy",          "(J)V",                     (void*)native_callStateDestroy },
    { "callStateGetAkeTopic",      "(J)Ljava/lang/String;",    (void*)native_callStateGetAkeTopic },
    { "callStateGetCurrentTopic",  "(J)Ljava/lang/String;",    (void*)native_callStateGetCurrentTopic },
    { "callStateGetSharedKey",     "(J)[B",                    (void*)native_callStateGetSharedKey },
    { "callStateGetTicket",        "(J)[B",                    (void*)native_callStateGetTicket },
    { "callStateGetSenderId",      "(J)Ljava/lang/String;",    (void*)native_callStateGetSenderId },
    { "callStateIsCaller",         "(J)Z",                     (void*)native_callStateIsCaller },
    { "callStateIsRecipient",      "(J)Z",                     (void*)native_callStateIsRecipient },
    { "callStateIsRuaActive",      "(J)Z",                     (void*)native_callStateIsRuaActive },
    { "callStateGetRemoteParty",   "(J)[Ljava/lang/String;",   (void*)native_callStateGetRemoteParty },
    { "callStateTransitionToRua",  "(J)V",                     (void*)native_callStateTransitionToRua },

    // AKE Protocol
    { "akeInit",       "(J)V",                              (void*)native_akeInit },
    { "akeRequest",    "(J)[B",                             (void*)native_akeRequest },
    { "akeResponse",   "(J[B)[B",                           (void*)native_akeResponse },
    { "akeComplete",   "(J[B)[B",                           (void*)native_akeComplete },
    { "akeFinalize",   "(J[B)V",                            (void*)native_akeFinalize },

    // RUA Protocol
    { "ruaDeriveTopic", "(J)Ljava/lang/String;",            (void*)native_ruaDeriveTopic },
    { "ruaInit",        "(J)V",                             (void*)native_ruaInit },
    { "ruaRequest",     "(J)[B",                            (void*)native_ruaRequest },
    { "ruaResponse",    "(J[B)[B",                          (void*)native_ruaResponse },
    { "ruaFinalize",    "(J[B)V",                           (void*)native_ruaFinalize },

    // Messages
    { "messageDeserialize",   "([B)J",                      (void*)native_messageDeserialize },
    { "messageDestroy",       "(J)V",                       (void*)native_messageDestroy },
    { "messageGetType",       "(J)I",                       (void*)native_messageGetType },
    { "messageGetSenderId",   "(J)Ljava/lang/String;",      (void*)native_messageGetSenderId },
    { "messageGetTopic",      "(J)Ljava/lang/String;",      (void*)native_messageGetTopic },
    { "messageCreateBye",     "(J)[B",                      (void*)native_messageCreateBye },
    { "messageCreateHeartbeat", "(J)[B",                    (void*)native_messageCreateHeartbeat },

    // DR Messaging
    { "drEncrypt",     "(J[B)[B",                           (void*)native_drEncrypt },
    { "drDecrypt",     "(J[B)[B",                           (void*)native_drDecrypt },

    // Enrollment
    { "enrollmentCreateRequest",    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)[[B", (void*)native_enrollmentCreateRequest },
    { "enrollmentFinalize",         "([B[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)J", (void*)native_enrollmentFinalize },
    { "enrollmentKeysDestroy",      "([B)V",                (void*)native_enrollmentKeysDestroy },

    // Ticket verification
    { "verifyTicket",  "([B[B)Z",                           (void*)native_verifyTicket },
};

jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK || !env) {
        return JNI_ERR;
    }
    // ensure the crypto backend is initialized once
    dia_init();

    jclass cls = env->FindClass(DIA_JNI_CLASS);
    if (!cls) {
        // Class not found: return an error to make the issue obvious
        return JNI_ERR;
    }
    if (env->RegisterNatives(cls, gMethods, sizeof(gMethods)/sizeof(gMethods[0])) != 0) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
