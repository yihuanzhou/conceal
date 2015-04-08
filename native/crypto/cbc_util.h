#ifndef _JAVA_COM_FACEBOOK_CRYPTO_CBC_UTIL_
#define _JAVA_COM_FACEBOOK_CRYPTO_CBC_UTIL_

#include <jni.h>
#include <openssl/evp.h>

typedef struct CBC_JNI_CTX {
  jbyte* key;
  jbyte* iv;
  EVP_CIPHER_CTX* cipherCtx;
} CBC_JNI_CTX;

extern const int CBC_ENCRYPT_MODE;
extern const int CBC_DECRYPT_MODE;

void Init_CBC_CTX_Ptr_Field(JNIEnv* env);

int Init_CBC(JNIEnv* env, jobject obj, jbyteArray key, jbyteArray iv, jint mode);

CBC_JNI_CTX* Create_CBC_JNI_CTX(jbyte* keyBytes, jbyte* ivBytes);

CBC_JNI_CTX* Get_CBC_JNI_CTX(JNIEnv* env, jobject obj);

EVP_CIPHER_CTX* Get_CBC_Cipher_CTX(JNIEnv* env, jobject obj);

void Set_CBC_JNI_CTX(JNIEnv* env, jobject obj, CBC_JNI_CTX* ctx);

void Destroy_CBC_JNI_CTX(CBC_JNI_CTX* ctx);

#endif // _JAVA_COM_FACEBOOK_CRYPTO_CBC_UTIL_

