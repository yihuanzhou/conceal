/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <gcm_util.h>
#include <util.h>

// Used globally.
const int GCM_ENCRYPT_MODE = 1;
const int GCM_DECRYPT_MODE = 0;

static const char* JAVA_GCM_CLASS = "com/facebook/crypto/cipher/NativeGCMCipher";

static const int GCM_KEY_LENGTH_IN_BYTES = 16;
static const int GCM_IV_LENGTH_IN_BYTES = 16;

// Cache field id.
static jfieldID fieldId = NULL;

void Init_GCM_CTX_Ptr_Field(JNIEnv* env) {
  if (!fieldId) {
    jclass gcmClass = (*env)->FindClass(env, JAVA_GCM_CLASS);
    fieldId = (*env)->GetFieldID(env, gcmClass, "mCtxPtr", "I");
  }
}

int Init_GCM(JNIEnv* env, jobject obj, jbyteArray key, jbyteArray iv, jint mode) {
  jbyte* keyBytes = (*env)->GetByteArrayElements(env, key, NULL);
  if (!keyBytes) {
    return CRYPTO_FAILURE;
  }

  jbyte* ivBytes = (*env)->GetByteArrayElements(env, iv, NULL);
  if (!ivBytes) {
    (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
    return CRYPTO_FAILURE;
  }

  GCM_JNI_CTX* ctx = Create_GCM_JNI_CTX(keyBytes, ivBytes);
  Set_GCM_JNI_CTX(env, obj, ctx);

  (*env)->ReleaseByteArrayElements(env, key, keyBytes, JNI_ABORT);
  (*env)->ReleaseByteArrayElements(env, iv, ivBytes, JNI_ABORT);

  if (mode == GCM_ENCRYPT_MODE) {
    if (!EVP_EncryptInit(ctx->cipherCtx, EVP_aes_128_gcm(), ctx->key, ctx->iv)) {
      return CRYPTO_FAILURE;
    }
  } else if (mode == GCM_DECRYPT_MODE) {
    if (!EVP_DecryptInit(ctx->cipherCtx, EVP_aes_128_gcm(), ctx->key, ctx->iv)) {
      return CRYPTO_FAILURE;
    }
  } else {
    return CRYPTO_FAILURE;
  }
  return CRYPTO_SUCCESS;
}

GCM_JNI_CTX* Create_GCM_JNI_CTX(jbyte* keyBytes, jbyte* ivBytes) {
  GCM_JNI_CTX* ctx = (GCM_JNI_CTX*) malloc(sizeof(GCM_JNI_CTX));
  if (!ctx) {
    return NULL;
  }

  ctx->key = (jbyte*) malloc(sizeof(jbyte) * GCM_KEY_LENGTH_IN_BYTES);
  if (!ctx->key) {
    free(ctx);
    return NULL;
  }

  ctx->iv = (jbyte*) malloc(sizeof(jbyte) * GCM_IV_LENGTH_IN_BYTES);
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

  memcpy(ctx->key, keyBytes, GCM_KEY_LENGTH_IN_BYTES);
  memcpy(ctx->iv, ivBytes, GCM_IV_LENGTH_IN_BYTES);
  return ctx;
}

GCM_JNI_CTX* Get_GCM_JNI_CTX(JNIEnv* env, jobject obj) {
  return (GCM_JNI_CTX*) Get_JNI_CTX(env, obj, fieldId);
}

EVP_CIPHER_CTX* Get_GCM_Cipher_CTX(JNIEnv* env, jobject obj) {
  GCM_JNI_CTX* jniCtxPtr = (GCM_JNI_CTX*) Get_GCM_JNI_CTX(env, obj);
  if (!jniCtxPtr) {
    return NULL;
  }

  return (EVP_CIPHER_CTX*) (jniCtxPtr->cipherCtx);
}

void Set_GCM_JNI_CTX(JNIEnv* env, jobject obj, GCM_JNI_CTX* ctx) {
  Set_JNI_CTX(env, obj, fieldId, (jint) ctx);
}

void Destroy_GCM_JNI_CTX(GCM_JNI_CTX* ctx) {
  EVP_CIPHER_CTX_free(ctx->cipherCtx);
  free(ctx->key);
  free(ctx->iv);
  free(ctx);
}

