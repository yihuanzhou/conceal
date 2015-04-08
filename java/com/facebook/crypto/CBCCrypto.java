package com.facebook.crypto;

import com.facebook.crypto.cipher.NativeCBCCipher;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.streams.NativeCBCCipherInputStream;
import com.facebook.crypto.util.NativeCryptoLibrary;

import java.io.IOException;
import java.io.InputStream;

public class CBCCrypto {

  private final NativeCryptoLibrary mNativeCryptoLibrary;

  public CBCCrypto(NativeCryptoLibrary nativeCryptoLibrary) {
    mNativeCryptoLibrary = nativeCryptoLibrary;
  }

  /**
   * Tells if crypto native library and this class can be used.
   * @return true if and only if libraries could be loaded successfully.
   */
  public boolean isAvailable() {
      try {
          mNativeCryptoLibrary.ensureCryptoLoaded();
          return true;
      } catch (Throwable t) {
          return false;
      }
  }

  /**
   * Returns a cipher stream for the crypto version and id.
   */
  public InputStream getCipherInputStream(InputStream cipherStream, byte[] key, byte[] iv)
      throws IOException, KeyChainException, CryptoInitializationException {
    NativeCBCCipher cbcCipher = new NativeCBCCipher(mNativeCryptoLibrary);
    cbcCipher.decryptInit(key, iv);

    return new NativeCBCCipherInputStream(cipherStream, cbcCipher);
  }
}
