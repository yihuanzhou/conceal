package com.facebook.crypto;

import java.io.IOException;
import java.io.InputStream;

import com.facebook.crypto.cipher.NativeCBCCipher;
import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.exception.KeyChainException;
import com.facebook.crypto.keychain.KeyChain;
import com.facebook.crypto.streams.NativeCBCCipherInputStream;
import com.facebook.crypto.util.Assertions;
import com.facebook.crypto.util.NativeCryptoLibrary;

/**
 * A helper class with common functionality required for cipher operations in {@link Crypto}.
 */
/* package */ class CBCCipherHelper {

    private final KeyChain mKeyChain;
    private final NativeCryptoLibrary mNativeCryptoLibrary;

    public CBCCipherHelper(KeyChain keyChain, NativeCryptoLibrary nativeCryptoLibrary) {
        mKeyChain = keyChain;
        mNativeCryptoLibrary = nativeCryptoLibrary;
    }

    /**
     * Returns a cipher stream for the crypto version and id.
     */
    public InputStream getCipherInputStream(InputStream cipherStream, byte cryptoVersion, byte cipherID)
            throws IOException, KeyChainException, CryptoInitializationException {

        Assertions.checkArgumentForIO(cryptoVersion == VersionCodes.CIPHER_SERALIZATION_VERSION,
                "Unexpected crypto version " + cryptoVersion);

        Assertions.checkArgumentForIO(cipherID == VersionCodes.CIPHER_ID,
                "Unexpected cipher ID " + cipherID);

        byte[] iv = new byte[NativeCBCCipher.IV_LENGTH];
        int read = cipherStream.read(iv);
        if (read != iv.length) {
            throw new IOException("Not enough bytes for iv: " + read);
        }

        NativeCBCCipher cbcCipher = new NativeCBCCipher(mNativeCryptoLibrary);
        cbcCipher.decryptInit(mKeyChain.getCipherKey(), iv);

        return new NativeCBCCipherInputStream(cipherStream, cbcCipher);
    }
}
