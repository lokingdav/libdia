#include <jni.h>
#include <stdexcept>
#include <vector>
#include "dia/dia_c.h"

// Helper: throw a Java RuntimeException with the given message
static void throwJavaException(JNIEnv* env, const char* msg) {
    jclass exClass = env->FindClass("java/lang/RuntimeException");
    if (exClass) env->ThrowNew(exClass, msg);
}

// Helper: copy native buffer → new Java byte[]
static jbyteArray toJavaByteArray(JNIEnv* env,
                                  const unsigned char* buf,
                                  size_t len) {
    jbyteArray arr = env->NewByteArray((jsize)len);
    env->SetByteArrayRegion(arr, 0, (jsize)len, reinterpret_cast<const jbyte*>(buf));
    free_byte_buffer((unsigned char*)buf);
    return arr;
}

extern "C" {
    // bindings will be defined here
} // extern "C"