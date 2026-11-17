#include <jni.h>
#include <unistd.h>

JNIEXPORT jint JNICALL Java_NativeHealth_answer(JNIEnv *env, jclass type) {
    (void)env;
    (void)type;
    return getpid() > 0 ? 42 : 0;
}
