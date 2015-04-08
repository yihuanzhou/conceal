#include <cbc_util.h>
#include <jni.h>
#include <openssl/evp.h>
#include <util.h>

static const int CBC_CIPHER_BLOCK_SIZE_BYTES = 16;

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeEncryptInit(
  JNIEnv* env,
  jobject obj,
  jbyteArray key,
  jbyteArray iv) {

  if (!Init_CBC(env, obj, key, iv, CBC_ENCRYPT_MODE)) {
    return CRYPTO_FAILURE;
  }

  EVP_CIPHER_CTX* ctx = Get_CBC_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeDecryptInit(
  JNIEnv* env,
  jobject obj,
  jbyteArray key,
  jbyteArray iv) {

  if (!Init_CBC(env, obj, key, iv, CBC_DECRYPT_MODE)) {
    return CRYPTO_FAILURE;
  }

  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeDestroy(
  JNIEnv* env,
  jobject obj) {

  CBC_JNI_CTX* ctx = Get_CBC_JNI_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  Destroy_CBC_JNI_CTX(ctx);
  Set_CBC_JNI_CTX(env, obj, 0);
  return CRYPTO_SUCCESS;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeEncryptUpdate(
  JNIEnv* env,
  jobject obj,
  jbyteArray data,
  jint offset,
  jint dataLength,
  jbyteArray output) {

  int bytesWritten = 0;
  EVP_CIPHER_CTX* ctx = Get_CBC_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  jbyte* outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
  if (!outputBytes) {
    return CRYPTO_FAILURE;
  }

  jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (!dataBytes) {
    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);
    return CRYPTO_FAILURE;
  }

  if (!EVP_EncryptUpdate(ctx, outputBytes, &bytesWritten, dataBytes + offset, dataLength)) {
    bytesWritten = CRYPTO_NO_BYTES_WRITTEN;
  }

  (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

  return bytesWritten;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeEncryptFinal(
  JNIEnv* env,
  jobject obj,
  jbyteArray data,
  jint offset) {

  int bytesWritten = 0;

  EVP_CIPHER_CTX* ctx = Get_CBC_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (!dataBytes) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  if (!EVP_EncryptFinal_ex(ctx, dataBytes+offset, &bytesWritten)) {
    bytesWritten = CRYPTO_NO_BYTES_WRITTEN;
  }

  (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

  return bytesWritten;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeDecryptUpdate(
  JNIEnv* env,
  jobject obj,
  jbyteArray data,
  jint offset,
  jint dataLength,
  jbyteArray output) {

  int bytesWritten = 0;
  EVP_CIPHER_CTX* ctx = Get_CBC_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_FAILURE;
  }

  jbyte* outputBytes = (*env)->GetByteArrayElements(env, output, NULL);
  if (!outputBytes) {
    return CRYPTO_FAILURE;
  }

  jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (!dataBytes) {
    (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);
    return CRYPTO_FAILURE;
  }

  if (!EVP_DecryptUpdate(ctx, outputBytes, &bytesWritten, dataBytes + offset, dataLength)) {
    bytesWritten = CRYPTO_NO_BYTES_WRITTEN;
  }

  (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, output, outputBytes, 0);

  return bytesWritten;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeDecryptFinal(
  JNIEnv* env,
  jobject obj,
  jbyteArray data) {

  int bytesWritten = 0;

  EVP_CIPHER_CTX* ctx = Get_CBC_Cipher_CTX(env, obj);
  if (!ctx) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  jbyte* dataBytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (!dataBytes) {
    return CRYPTO_NO_BYTES_WRITTEN;
  }

  if (!EVP_DecryptFinal_ex(ctx, dataBytes, &bytesWritten)) {
    bytesWritten = CRYPTO_NO_BYTES_WRITTEN;
  }

  (*env)->ReleaseByteArrayElements(env, data, dataBytes, JNI_ABORT);

  return bytesWritten;
}

JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeGetCipherBlockSize(
  JNIEnv* env) {

  return CBC_CIPHER_BLOCK_SIZE_BYTES;
}

// Give the java layer access to C constants.
JNIEXPORT int JNICALL Java_com_facebook_crypto_cipher_NativeCBCCipher_nativeFailure(
  JNIEnv* env,
  jobject obj) {

  return CRYPTO_FAILURE;
}
