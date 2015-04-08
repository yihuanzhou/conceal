/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto;

import android.annotation.TargetApi;
import android.os.Build;

import com.facebook.crypto.cipher.NativeGCMCipher;

import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.GCMBlockCipher;
import org.spongycastle.crypto.params.AEADParameters;
import org.spongycastle.crypto.params.KeyParameter;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class BouncyCastleHelper {

  public static Result bouncyCastleEncrypt(byte[] data, byte[] key, byte[] iv, byte[] aadData)
      throws UnsupportedEncodingException, InvalidCipherTextException {
    GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
    byte[] gcmOut = new byte[CryptoTestUtils.NUM_DATA_BYTES + NativeGCMCipher.TAG_LENGTH];
    KeyParameter keyParameter = new KeyParameter(key);

    // Add aad data.
    AEADParameters params = new AEADParameters(
          keyParameter,
          NativeGCMCipher.TAG_LENGTH * 8,
          iv,
          aadData);

    // Init encryption.
    gcm.init(true, params);
    int written = gcm.processBytes(data, 0, data.length, gcmOut, 0);
    written += gcm.doFinal(gcmOut, written);

    byte[] bouncyCastleOut = Arrays.copyOfRange(gcmOut, 0, written);
    byte[] cipherText =
        Arrays.copyOfRange(bouncyCastleOut, 0, CryptoTestUtils.NUM_DATA_BYTES);
    byte[] tag =
        Arrays.copyOfRange(bouncyCastleOut, CryptoTestUtils.NUM_DATA_BYTES, bouncyCastleOut.length);
    return new Result(cipherText, tag);
  }

  public static byte[] bouncyCastleCBCEncrypt(byte[] data, byte[] key, byte[] iv) 
      throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding" /*transformation*/, "BC" /*provider*/);
    SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
    return cipher.doFinal(data);
  }

  public static class Result {

    public final byte[] cipherText;
    public final byte[] tag;

    public Result(byte[] cipherText, byte[] tag) {
      this.cipherText = cipherText;
      this.tag = tag;
    }
  }
}

