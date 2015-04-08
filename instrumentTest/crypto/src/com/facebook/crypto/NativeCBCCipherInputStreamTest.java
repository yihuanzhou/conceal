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
import android.test.InstrumentationTestCase;

import com.facebook.crypto.cipher.NativeCBCCipher;
import com.facebook.crypto.cipher.NativeGCMCipher;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.crypto.util.SystemNativeCryptoLibrary;
import com.google.common.io.ByteStreams;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Random;

@TargetApi(Build.VERSION_CODES.GINGERBREAD)
public class NativeCBCCipherInputStreamTest extends InstrumentationTestCase {

  private CBCCrypto mCrypto;
  private NativeCryptoLibrary mNativeCryptoLibrary;
  private byte[] mData;

  private ByteArrayInputStream mCipherInputStream;
  private byte[] mCipheredData;
  private byte[] mIV;
  private byte[] mKey;

  protected void setUp() throws Exception {
    super.setUp();
    mNativeCryptoLibrary = new SystemNativeCryptoLibrary();
    mCrypto = new CBCCrypto(mNativeCryptoLibrary);
    byte[] b = new byte[20];
    mIV = new byte[NativeCBCCipher.IV_LENGTH];
    new Random().nextBytes(mIV);
    mKey = new byte[NativeCBCCipher.KEY_LENGTH];
    new Random().nextBytes(mKey);

    // Encrypt some data before each test.
    mData = new byte[CryptoTestUtils.NUM_DATA_BYTES];

    mCipheredData = BouncyCastleHelper.bouncyCastleCBCEncrypt(mData, mKey, mIV);
    mCipherInputStream = new ByteArrayInputStream(mCipheredData);
  }

  public void testCompatibleWithBouncyCastle() throws Exception {
    InputStream inputStream = mCrypto.getCipherInputStream(mCipherInputStream, mKey, mIV);
    byte[] decryptedData = ByteStreams.toByteArray(inputStream);
    inputStream.close();
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT, Arrays.equals(mData, decryptedData));
  }

  public void testDecryptValidDataInSmallIncrements() throws Exception {
    InputStream inputStream = mCrypto.getCipherInputStream(mCipherInputStream, mKey, mIV);

    ByteArrayOutputStream decryptedData = new ByteArrayOutputStream();
    byte[] buffer = new byte[NativeCBCCipher.KEY_LENGTH / 6];
    int read;
    while ((read = inputStream.read(buffer)) != -1) {
//      assertTrue(read > 0);
      decryptedData.write(buffer, 0, read);
    }

    inputStream.close();
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT,
        Arrays.equals(mData, decryptedData.toByteArray()));
  }

  public void testDecryptValidDataReadUsingOffsets() throws Exception {
    byte[] decryptedData = new byte[CryptoTestUtils.NUM_DATA_BYTES];
    InputStream inputStream = mCrypto.getCipherInputStream(mCipherInputStream, mKey, mIV);

    int readSize = decryptedData.length / 2;
    ByteStreams.readFully(inputStream, decryptedData, 0, readSize);
    ByteStreams.readFully(inputStream, decryptedData, readSize, decryptedData.length - readSize);

    // read the remaining bytes.
    ByteStreams.toByteArray(inputStream);
    inputStream.close();
    assertTrue(CryptoTestUtils.DECRYPTED_DATA_IS_DIFFERENT, Arrays.equals(mData, decryptedData));
  }
}
