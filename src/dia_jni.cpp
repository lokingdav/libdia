// dia_jni.cpp
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

static bool checkLen(JNIEnv* env, jbyteArray arr, jsize want, const char* name) {
    if (!arr) { throwIllegalArg(env, (std::string(name) + " is null").c_str()); return false; }
    const jsize got = env->GetArrayLength(arr);
    if (got != want) {
        throwIllegalArg(env, (std::string(name) + " wrong length").c_str());
        return false;
    }
    return true;
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

static jbyteArray makeByteArray(JNIEnv* env, const std::vector<unsigned char>& v) {
    return makeByteArray(env, v.data(), v.size());
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

/* Java byte[][] → vectors + raw pointer arrays */
struct CArrayBytes {
    std::vector<std::vector<unsigned char>> store;
    std::vector<const unsigned char*> ptrs;
    std::vector<size_t> lens;
};

static CArrayBytes toCArrayBytes(JNIEnv* env, jobjectArray jarr) {
    CArrayBytes out;
    if (!jarr) return out;
    const jsize n = env->GetArrayLength(jarr);
    out.store.resize(n);
    out.ptrs.resize(n);
    out.lens.resize(n);
    for (jsize i = 0; i < n; ++i) {
        auto elt = static_cast<jbyteArray>(env->GetObjectArrayElement(jarr, i));
        if (elt) {
            out.store[i] = getBytes(env, elt);
            out.ptrs[i] = out.store[i].data();
            out.lens[i] = out.store[i].size();
            env->DeleteLocalRef(elt);
        } else {
            out.ptrs[i] = nullptr;
            out.lens[i] = 0;
        }
    }
    return out;
}

static std::vector<uint32_t> toU32(JNIEnv* env, jintArray a) {
    std::vector<uint32_t> out;
    if (!a) return out;
    const jsize n = env->GetArrayLength(a);
    out.resize(n);
    if (n > 0) {
        std::vector<jint> tmp(n);
        env->GetIntArrayRegion(a, 0, n, tmp.data());
        for (jsize i = 0; i < n; ++i) out[i] = static_cast<uint32_t>(tmp[i]);
    }
    return out;
}

/* ================================== DH ==================================== */

static jobjectArray native_dhKeygen(JNIEnv* env, jclass) {
    unsigned char sk[DIA_FR_LEN], pk[DIA_G1_LEN];
    if (!rcIsOk(env, "dia_dh_keygen", dia_dh_keygen(sk, pk))) return nullptr;

    jobjectArray out = make2DByteArray(env, 2);
    set2DByteArrayElem(env, out, 0, sk, DIA_FR_LEN);
    set2DByteArrayElem(env, out, 1, pk, DIA_G1_LEN);
    return out;
}

static jbyteArray native_dhComputeSecret(JNIEnv* env, jclass,
                                         jbyteArray jsk, jbyteArray jpk) {
    if (!checkLen(env, jsk, DIA_FR_LEN, "sk")) return nullptr;
    if (!checkLen(env, jpk, DIA_G1_LEN, "peerPk")) return nullptr;

    auto sk = getBytes(env, jsk);
    auto pk = getBytes(env, jpk);

    unsigned char sec[DIA_G1_LEN];
    if (!rcIsOk(env, "dia_dh_compute_secret",
                dia_dh_compute_secret(sk.data(), pk.data(), sec))) {
        return nullptr;
    }
    return makeByteArray(env, sec, DIA_G1_LEN);
}

/* ================================ VOPRF ================================= */

static jobjectArray native_voprfKeygen(JNIEnv* env, jclass) {
    unsigned char sk[DIA_FR_LEN], pk[DIA_G2_LEN];
    if (!rcIsOk(env, "dia_voprf_keygen", dia_voprf_keygen(sk, pk))) return nullptr;

    jobjectArray out = make2DByteArray(env, 2);
    set2DByteArrayElem(env, out, 0, sk, DIA_FR_LEN);
    set2DByteArrayElem(env, out, 1, pk, DIA_G2_LEN);
    return out;
}

static jobjectArray native_voprfBlind(JNIEnv* env, jclass, jbyteArray input) {
    std::vector<unsigned char> in = getBytes(env, input);
    unsigned char blinded[DIA_G1_LEN], blind[DIA_FR_LEN];
    if (!rcIsOk(env, "dia_voprf_blind",
                dia_voprf_blind(in.data(), in.size(), blinded, blind))) return nullptr;

    jobjectArray out = make2DByteArray(env, 2);
    set2DByteArrayElem(env, out, 0, blinded, DIA_G1_LEN);
    set2DByteArrayElem(env, out, 1, blind, DIA_FR_LEN);
    return out;
}

static jbyteArray native_voprfEvaluate(JNIEnv* env, jclass, jbyteArray blinded, jbyteArray sk) {
    if (!checkLen(env, blinded, DIA_G1_LEN, "blinded")) return nullptr;
    if (!checkLen(env, sk, DIA_FR_LEN, "sk")) return nullptr;

    auto B = getBytes(env, blinded);
    auto S = getBytes(env, sk);

    unsigned char element[DIA_G1_LEN];
    if (!rcIsOk(env, "dia_voprf_evaluate",
                dia_voprf_evaluate(B.data(), S.data(), element))) return nullptr;
    return makeByteArray(env, element, DIA_G1_LEN);
}

static jbyteArray native_voprfUnblind(JNIEnv* env, jclass, jbyteArray element, jbyteArray blind) {
    if (!checkLen(env, element, DIA_G1_LEN, "element")) return nullptr;
    if (!checkLen(env, blind, DIA_FR_LEN, "blind")) return nullptr;

    auto E = getBytes(env, element);
    auto R = getBytes(env, blind);

    unsigned char Y[DIA_G1_LEN];
    if (!rcIsOk(env, "dia_voprf_unblind",
                dia_voprf_unblind(E.data(), R.data(), Y))) return nullptr;
    return makeByteArray(env, Y, DIA_G1_LEN);
}

static jboolean native_voprfVerify(JNIEnv* env, jclass,
                                   jbyteArray input, jbyteArray Y, jbyteArray pk) {
    if (!checkLen(env, Y, DIA_G1_LEN, "Y")) return JNI_FALSE;
    if (!checkLen(env, pk, DIA_G2_LEN, "pk")) return JNI_FALSE;

    auto In = getBytes(env, input);
    auto Yb = getBytes(env, Y);
    auto Pk = getBytes(env, pk);

    int valid = 0;
    if (!rcIsOk(env, "dia_voprf_verify",
                dia_voprf_verify(In.data(), In.size(), Yb.data(), Pk.data(), &valid))) {
        return JNI_FALSE;
    }
    return valid ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_voprfVerifyBatch(JNIEnv* env, jclass,
                                        jobjectArray inputs, jobjectArray Ys, jbyteArray pk) {
    if (!checkLen(env, pk, DIA_G2_LEN, "pk")) return JNI_FALSE;

    CArrayBytes ins = toCArrayBytes(env, inputs);
    CArrayBytes outs = toCArrayBytes(env, Ys);
    if (ins.ptrs.size() != outs.ptrs.size()) {
        throwIllegalArg(env, "inputs and Ys length mismatch");
        return JNI_FALSE;
    }
    const size_t n = outs.ptrs.size();

    std::vector<unsigned char> Ycat(n * DIA_G1_LEN);
    for (size_t i = 0; i < n; ++i) {
        if (outs.lens[i] != DIA_G1_LEN) {
            throwIllegalArg(env, "Ys[i] wrong length");
            return JNI_FALSE;
        }
        std::memcpy(Ycat.data() + i * DIA_G1_LEN, outs.ptrs[i], DIA_G1_LEN);
    }

    auto Pk = getBytes(env, pk);
    int valid = 0;
    if (!rcIsOk(env, "dia_voprf_verify_batch",
                dia_voprf_verify_batch(ins.ptrs.data(), ins.lens.data(), n,
                                       Ycat.data(), Pk.data(), &valid))) {
        return JNI_FALSE;
    }
    return valid ? JNI_TRUE : JNI_FALSE;
}

/* ================================= AMF =================================== */

static jobjectArray native_amfKeygen(JNIEnv* env, jclass) {
    unsigned char sk[DIA_FR_LEN], pk[DIA_G1_LEN];
    if (!rcIsOk(env, "dia_amf_keygen", dia_amf_keygen(sk, pk))) return nullptr;

    jobjectArray out = make2DByteArray(env, 2);
    set2DByteArrayElem(env, out, 0, sk, DIA_FR_LEN);
    set2DByteArrayElem(env, out, 1, pk, DIA_G1_LEN);
    return out;
}

static jbyteArray native_amfFrank(JNIEnv* env, jclass,
                                  jbyteArray skSender, jbyteArray pkReceiver,
                                  jbyteArray pkJudge, jbyteArray msg) {
    if (!checkLen(env, skSender, DIA_FR_LEN, "skSender")) return nullptr;
    if (!checkLen(env, pkReceiver, DIA_G1_LEN, "pkReceiver")) return nullptr;
    if (!checkLen(env, pkJudge, DIA_G1_LEN, "pkJudge")) return nullptr;

    auto S  = getBytes(env, skSender);
    auto PR = getBytes(env, pkReceiver);
    auto PJ = getBytes(env, pkJudge);
    auto M  = getBytes(env, msg);

    unsigned char* sig = nullptr;
    size_t sig_len = 0;
    int rc = dia_amf_frank(S.data(), PR.data(), PJ.data(),
                           M.data(), M.size(), &sig, &sig_len);
    if (!rcIsOk(env, "dia_amf_frank", rc)) return nullptr;

    jbyteArray out = makeByteArray(env, sig, sig_len);
    free_byte_buffer(sig);
    return out;
}

static jboolean native_amfVerify(JNIEnv* env, jclass,
                                 jbyteArray pkSender, jbyteArray skReceiver,
                                 jbyteArray pkJudge, jbyteArray msg, jbyteArray sig) {
    if (!checkLen(env, pkSender, DIA_G1_LEN, "pkSender")) return JNI_FALSE;
    if (!checkLen(env, skReceiver, DIA_FR_LEN, "skReceiver")) return JNI_FALSE;
    if (!checkLen(env, pkJudge, DIA_G1_LEN, "pkJudge")) return JNI_FALSE;

    auto PS = getBytes(env, pkSender);
    auto SR = getBytes(env, skReceiver);
    auto PJ = getBytes(env, pkJudge);
    auto M  = getBytes(env, msg);
    auto SB = getBytes(env, sig);

    int valid = 0;
    if (!rcIsOk(env, "dia_amf_verify",
                dia_amf_verify(PS.data(), SR.data(), PJ.data(),
                               M.data(), M.size(), SB.data(), SB.size(), &valid))) {
        return JNI_FALSE;
    }
    return valid ? JNI_TRUE : JNI_FALSE;
}

static jboolean native_amfJudge(JNIEnv* env, jclass,
                                jbyteArray pkSender, jbyteArray pkReceiver,
                                jbyteArray skJudge, jbyteArray msg, jbyteArray sig) {
    if (!checkLen(env, pkSender, DIA_G1_LEN, "pkSender")) return JNI_FALSE;
    if (!checkLen(env, pkReceiver, DIA_G1_LEN, "pkReceiver")) return JNI_FALSE;
    if (!checkLen(env, skJudge, DIA_FR_LEN, "skJudge")) return JNI_FALSE;

    auto PS = getBytes(env, pkSender);
    auto PR = getBytes(env, pkReceiver);
    auto SJ = getBytes(env, skJudge);
    auto M  = getBytes(env, msg);
    auto SB = getBytes(env, sig);

    int valid = 0;
    if (!rcIsOk(env, "dia_amf_judge",
                dia_amf_judge(PS.data(), PR.data(), SJ.data(),
                              M.data(), M.size(), SB.data(), SB.size(), &valid))) {
        return JNI_FALSE;
    }
    return valid ? JNI_TRUE : JNI_FALSE;
}

/* ================================= BBS =================================== */

static jobjectArray native_bbsKeygen(JNIEnv* env, jclass) {
    unsigned char sk[DIA_FR_LEN], pk[DIA_G2_LEN];
    if (!rcIsOk(env, "dia_bbs_keygen", dia_bbs_keygen(sk, pk))) return nullptr;

    jobjectArray out = make2DByteArray(env, 2);
    set2DByteArrayElem(env, out, 0, sk, DIA_FR_LEN);
    set2DByteArrayElem(env, out, 1, pk, DIA_G2_LEN);
    return out;
}

// BBSSign -> returns [[B] of length 2: {A (G1), e (Fr)}
static jobjectArray native_bbsSign(JNIEnv* env, jclass, jobjectArray msgs, jbyteArray sk) {
    if (!checkLen(env, sk, DIA_FR_LEN, "sk")) return nullptr;

    CArrayBytes M = toCArrayBytes(env, msgs);
    auto S = getBytes(env, sk);

    unsigned char A[DIA_G1_LEN], e[DIA_FR_LEN];
    int rc = dia_bbs_sign(
        (const unsigned char* const*)M.ptrs.data(),
        M.lens.data(),
        M.ptrs.size(),
        S.data(),
        A, e
    );
    if (!rcIsOk(env, "dia_bbs_sign", rc)) return nullptr;

    jobjectArray out = make2DByteArray(env, 2);
    set2DByteArrayElem(env, out, 0, A, DIA_G1_LEN);
    set2DByteArrayElem(env, out, 1, e, DIA_FR_LEN);
    return out;
}

static jboolean native_bbsVerify(JNIEnv* env, jclass,
                                 jobjectArray msgs, jbyteArray pk, jbyteArray A, jbyteArray e_) {
    if (!checkLen(env, pk, DIA_G2_LEN, "pk")) return JNI_FALSE;
    if (!checkLen(env, A,  DIA_G1_LEN, "A"))  return JNI_FALSE;
    if (!checkLen(env, e_, DIA_FR_LEN, "e"))  return JNI_FALSE;

    CArrayBytes M = toCArrayBytes(env, msgs);
    auto Pk = getBytes(env, pk);
    auto Aa = getBytes(env, A);
    auto Ee = getBytes(env, e_);

    int valid = 0;
    if (!rcIsOk(env, "dia_bbs_verify",
                dia_bbs_verify(
                    (const unsigned char* const*)M.ptrs.data(),
                    M.lens.data(),
                    M.ptrs.size(),
                    Pk.data(),
                    Aa.data(),
                    Ee.data(),
                    &valid))) {
        return JNI_FALSE;
    }
    return valid ? JNI_TRUE : JNI_FALSE;
}

static jbyteArray native_bbsCreateProof(JNIEnv* env, jclass,
                                        jobjectArray msgs, jintArray discloseIdx1b,
                                        jbyteArray pk, jbyteArray A, jbyteArray e, jbyteArray nonce) {
    if (!checkLen(env, pk, DIA_G2_LEN, "pk")) return nullptr;
    if (!checkLen(env, A,  DIA_G1_LEN, "A"))  return nullptr;
    if (!checkLen(env, e,  DIA_FR_LEN, "e"))  return nullptr;

    CArrayBytes M = toCArrayBytes(env, msgs);
    auto idx = toU32(env, discloseIdx1b);
    auto Pk = getBytes(env, pk);
    auto Aa = getBytes(env, A);
    auto Ee = getBytes(env, e);
    auto N  = getBytes(env, nonce);

    unsigned char* blob = nullptr;
    size_t blob_len = 0;

    int rc = dia_bbs_proof_create(
        (const unsigned char* const*)M.ptrs.data(),
        M.lens.data(),
        M.ptrs.size(),
        idx.empty() ? nullptr : idx.data(),
        idx.size(),
        Pk.data(),
        Aa.data(),
        Ee.data(),
        N.data(), N.size(),
        &blob, &blob_len
    );
    if (!rcIsOk(env, "dia_bbs_proof_create", rc)) return nullptr;

    jbyteArray out = makeByteArray(env, blob, blob_len);
    free_byte_buffer(blob);
    return out;
}

static jboolean native_bbsVerifyProof(JNIEnv* env, jclass,
                                      jintArray disclosedIdx1b, jobjectArray disclosedMsgs,
                                      jbyteArray pk, jbyteArray nonce, jbyteArray proof) {
    if (!checkLen(env, pk, DIA_G2_LEN, "pk")) return JNI_FALSE;

    auto idx = toU32(env, disclosedIdx1b);
    CArrayBytes D = toCArrayBytes(env, disclosedMsgs);
    if (D.ptrs.size() != idx.size()) {
        throwIllegalArg(env, "disclosedIdx and disclosedMsgs length mismatch");
        return JNI_FALSE;
    }

    auto Pk = getBytes(env, pk);
    auto N  = getBytes(env, nonce);
    auto Pr = getBytes(env, proof);

    int valid = 0;
    if (!rcIsOk(env, "dia_bbs_proof_verify",
                dia_bbs_proof_verify(
                    idx.empty() ? nullptr : idx.data(),
                    (const unsigned char* const*)D.ptrs.data(),
                    D.lens.data(),
                    D.ptrs.size(),
                    Pk.data(),
                    N.data(), N.size(),
                    Pr.data(), Pr.size(),
                    &valid))) {
        return JNI_FALSE;
    }
    return valid ? JNI_TRUE : JNI_FALSE;
}

/* ============================ Registration =============================== */

static JNINativeMethod gMethods[] = {
    // DH
    { "dhKeygen",         "()[[B",                          (void*)native_dhKeygen },
    { "dhComputeSecret",  "([B[B)[B",                       (void*)native_dhComputeSecret },

    // VOPRF
    { "voprfKeygen",      "()[[B",                          (void*)native_voprfKeygen },
    { "voprfBlind",       "([B)[[B",                        (void*)native_voprfBlind },
    { "voprfEvaluate",    "([B[B)[B",                       (void*)native_voprfEvaluate },
    { "voprfUnblind",     "([B[B)[B",                       (void*)native_voprfUnblind },
    { "voprfVerify",      "([B[B[B)Z",                      (void*)native_voprfVerify },
    { "voprfVerifyBatch", "([[B[[B[B)Z",                    (void*)native_voprfVerifyBatch },

    // AMF
    { "amfKeygen",        "()[[B",                          (void*)native_amfKeygen },
    { "amfFrank",         "([B[B[B[B)[B",                   (void*)native_amfFrank },
    { "amfVerify",        "([B[B[B[B[B)Z",                  (void*)native_amfVerify },
    { "amfJudge",         "([B[B[B[B[B)Z",                  (void*)native_amfJudge },

    // BBS
    { "bbsKeygen",        "()[[B",                          (void*)native_bbsKeygen },
    { "bbsSign",          "([[B[B)[[B",                     (void*)native_bbsSign },
    { "bbsVerify",        "([[B[B[B[B)Z",                   (void*)native_bbsVerify },
    { "bbsCreateProof",   "([[B[I[B[B[B[B)[B",              (void*)native_bbsCreateProof },
    { "bbsVerifyProof",   "([I[[B[B[B[B)Z",                 (void*)native_bbsVerifyProof },
};

jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK || !env) {
        return JNI_ERR;
    }
    // ensure the crypto backend is initialized once
    init_dia();

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
