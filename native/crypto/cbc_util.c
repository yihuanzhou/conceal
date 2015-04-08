#include <cbc_util.h>
#include <util.h>

// Used globally.
const int CBC_ENCRYPT_MODE = 1;
const int CBC_DECRYPT_MODE = 0;

static const char* JAVA_CBC_CLASS = "com/facebook/crypto/cipher/NativeCBCCipher";

static const int CBC_KEY_LENGTH_IN_BYTES = 16;
static const int CBC_IV_LENGTH_IN_BYTES = 16;

// Cache field id.
static jfieldID fieldId = NULL;

void Init_CBC_CTX_Ptr_Field(JNIEnv* env) {
  if (!fieldId) {
    jclass cbcClass = (*env)->FindClass(env, JAVA_CBC_CLASS);
    fieldId = (*env)->GetFieldID(env, cbcClass, "mCtxPtr", "I");
  }
}

int Init_CBC(JNIEnv* env, jobject obj, jbyteArray key, jbyteArray iv, jint mode) {
  jbyte* keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
  if (!keyBytes) {
    return CRYPTO_FAILURE;
  }

  jbyte* ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
  if (!ivBytes) {
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    return CRYPTO_FAILURE;
  }

  CBC_JNI_CTX* ctx = Create_CBC_JNI_CTX(keyBytes, ivBytes);
  Set_CBC_JNI_CTX(env, obj, ctx);

  int keyLength = (*env)->GetArrayLength(env, key);
  (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

  if (mode == CBC_ENCRYPT_MODE) {
    switch (keyLength) {
      case 16: {
        if (!EVP_EncryptInit(ctx->cipherCtx, EVP_aes_128_cbc(), ctx->key, ctx->iv)) {
          return CRYPTO_FAILURE;
        }                
        break;
      }
      case 24: {
        if (!EVP_EncryptInit(ctx->cipherCtx, EVP_aes_192_cbc(), ctx->key, ctx->iv)) {
          return CRYPTO_FAILURE;
        }                
        break;
      }
      case 32: {
        if (!EVP_EncryptInit(ctx->cipherCtx, EVP_aes_256_cbc(), ctx->key, ctx->iv)) {
          return CRYPTO_FAILURE;
        }                
        break;
      }
    }
  } else if (mode == CBC_DECRYPT_MODE) {
    switch (keyLength) {
      case 16: {
        if (!EVP_DecryptInit(ctx->cipherCtx, EVP_aes_128_cbc(), ctx->key, ctx->iv)) {
          return CRYPTO_FAILURE;
        }                
        break;
      }
      case 24: {
        if (!EVP_DecryptInit(ctx->cipherCtx, EVP_aes_192_cbc(), ctx->key, ctx->iv)) {
          return CRYPTO_FAILURE;
        }                
        break;
      }
      case 32: {
        if (!EVP_DecryptInit(ctx->cipherCtx, EVP_aes_256_cbc(), ctx->key, ctx->iv)) {
          return CRYPTO_FAILURE;
        }                
        break;
      }
    }
  } else {
    return CRYPTO_FAILURE;
  }
  return CRYPTO_SUCCESS;
}

CBC_JNI_CTX* Create_CBC_JNI_CTX(jbyte* keyBytes, jbyte* ivBytes) {
  CBC_JNI_CTX* ctx = (CBC_JNI_CTX*) malloc(sizeof(CBC_JNI_CTX));
  if (!ctx) {
    return NULL;
  }

  ctx->key = (jbyte*) malloc(sizeof(jbyte) * CBC_KEY_LENGTH_IN_BYTES);
  if (!ctx->key) {
    free(ctx);
    return NULL;
  }

  ctx->iv = (jbyte*) malloc(sizeof(jbyte) * CBC_IV_LENGTH_IN_BYTES);
  if (!ctx->iv) {
    free(ctx->key);
    free(ctx);
    return NULL;
  }

  ctx->cipherCtx = EVP_CIPHER_CTX_new();
  if (!ctx->cipherCtx) {
    free(ctx->iv);
    free(ctx->key);
    free(ctx);
    return NULL;
  }

  memcpy(ctx->key, keyBytes, CBC_KEY_LENGTH_IN_BYTES);
  memcpy(ctx->iv, ivBytes, CBC_IV_LENGTH_IN_BYTES);
  return ctx;
}

CBC_JNI_CTX* Get_CBC_JNI_CTX(JNIEnv* env, jobject obj) {
  return (CBC_JNI_CTX*) Get_JNI_CTX(env, obj, fieldId);
}

EVP_CIPHER_CTX* Get_CBC_Cipher_CTX(JNIEnv* env, jobject obj) {
  CBC_JNI_CTX* jniCtxPtr = (CBC_JNI_CTX*) Get_CBC_JNI_CTX(env, obj);
  if (!jniCtxPtr) {
    return NULL;
  }

  return (EVP_CIPHER_CTX*) (jniCtxPtr->cipherCtx);
}

void Set_CBC_JNI_CTX(JNIEnv* env, jobject obj, CBC_JNI_CTX* ctx) {
  Set_JNI_CTX(env, obj, fieldId, (jint) ctx);
}

void Destroy_CBC_JNI_CTX(CBC_JNI_CTX* ctx) {
  EVP_CIPHER_CTX_free(ctx->cipherCtx);
  free(ctx->key);
  free(ctx->iv);
  free(ctx);
}

