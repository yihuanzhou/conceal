package com.facebook.crypto.cipher;

import com.facebook.crypto.exception.CryptoInitializationException;
import com.facebook.crypto.util.Assertions;
import com.facebook.crypto.util.NativeCryptoLibrary;
import com.facebook.proguard.annotations.DoNotStrip;

import java.util.Locale;

/**
 * Various native functions to encrypt/decrypt data using CBC.
 */
@DoNotStrip
public class NativeCBCCipher {

    public static final String FAILURE = "Failure";

    private static final String CIPHER_ALREADY_INIT = "Cipher has already been initialized";
    private static final String CIPHER_NOT_INIT = "Cipher has not been initialized";
    private static final String CIPHER_NOT_FINALIZED = "Cipher has not been finalized";

    public static final int KEY_LENGTH = 16;
    public static final int IV_LENGTH = 16;

    private STATE mCurrentState = STATE.UNINITIALIZED;

    private final NativeCryptoLibrary mNativeCryptoLibrary;

    private enum STATE {
        UNINITIALIZED,
        ENCRYPT_INITIALIZED,
        DECRYPT_INITIALIZED,
        ENCRYPT_FINALIZED,
        DECRYPT_FINALIZED,
    };

    public NativeCBCCipher(NativeCryptoLibrary nativeCryptoLibrary) {
        mNativeCryptoLibrary = nativeCryptoLibrary;
    }

    public void encryptInit(byte[] key, byte[] iv)
            throws NativeCBCCipherException, CryptoInitializationException {
        Assertions.checkState(mCurrentState == STATE.UNINITIALIZED, CIPHER_ALREADY_INIT);
        mNativeCryptoLibrary.ensureCryptoLoaded();
        if (nativeEncryptInit(key, iv) == nativeFailure()) {
            throw new NativeCBCCipherException("encryptInit");
        }
        mCurrentState = STATE.ENCRYPT_INITIALIZED;
    }
    public void decryptInit(byte[] key, byte[] iv)
            throws NativeCBCCipherException, CryptoInitializationException {
        Assertions.checkState(mCurrentState == STATE.UNINITIALIZED, CIPHER_ALREADY_INIT);
        mNativeCryptoLibrary.ensureCryptoLoaded();
        if (nativeDecryptInit(key, iv) == nativeFailure()) {
            throw new NativeCBCCipherException("decryptInit");
        }
        mCurrentState = STATE.DECRYPT_INITIALIZED;
    }

    public int encryptUpdate(byte[] data, int offset, int dataLen, byte[] output)
            throws NativeCBCCipherException {
        ensureInInitalizedState();
        int bytesRead = nativeEncryptUpdate(data, offset, dataLen, output);
        if (bytesRead < 0) {
            throw new NativeCBCCipherException(
                    formatStrLocaleSafe(
                            "encryptUpdate: Offset = %d; DataLen = %d; Result = %d",
                            offset,
                            dataLen,
                            bytesRead));
        }
        return bytesRead;
    }

    public int decryptUpdate(byte[] data, int offset, int dataLen, byte[] output)
            throws NativeCBCCipherException {
        ensureInInitalizedState();
        int bytesRead = nativeDecryptUpdate(data, offset, dataLen, output);
        if (bytesRead < 0) {
            throw new NativeCBCCipherException(
                    formatStrLocaleSafe(
                            "decryptUpdate: Offset = %d; DataLen = %d; Result = %d",
                            offset,
                            dataLen,
                            bytesRead));
        }
        return bytesRead;
    }

    public int encryptFinal(byte[] data, int offset)
            throws NativeCBCCipherException {
        Assertions.checkState(mCurrentState == STATE.ENCRYPT_INITIALIZED, CIPHER_NOT_INIT);
        mCurrentState = STATE.ENCRYPT_FINALIZED;
        int bytesRead = nativeEncryptFinal(data, offset);
        if (bytesRead < 0) {
            throw new NativeCBCCipherException("encryptFinal");
        }
        return bytesRead;
    }

    public int decryptFinal(byte[] data) throws NativeCBCCipherException {
        Assertions.checkState(mCurrentState == STATE.DECRYPT_INITIALIZED, CIPHER_NOT_INIT);
        mCurrentState = STATE.DECRYPT_FINALIZED;
        int bytesRead = nativeDecryptFinal(data);
        if (bytesRead < 0) {
            throw new NativeCBCCipherException(
                formatStrLocaleSafe(
                    "decryptFinal read %d",
                    bytesRead));
        }
        return bytesRead;
    }

    public void destroy() throws NativeCBCCipherException {
        ensureInFinalizedState();
        if (nativeDestroy() == nativeFailure()) {
            throw new NativeCBCCipherException("destroy");
        }
        mCurrentState = STATE.UNINITIALIZED;
    }

    public int getCipherBlockSize() {
        ensureInInitalizedState();
        return nativeGetCipherBlockSize();
    }

    private void ensureInInitalizedState() {
        boolean initialized =
                mCurrentState == STATE.DECRYPT_INITIALIZED ||
                        mCurrentState == STATE.ENCRYPT_INITIALIZED;
        Assertions.checkState(initialized, CIPHER_NOT_INIT);
    }

    private void ensureInFinalizedState() {
        boolean finalized =
                mCurrentState == STATE.DECRYPT_FINALIZED ||
                        mCurrentState == STATE.ENCRYPT_FINALIZED;
        Assertions.checkState(finalized, CIPHER_NOT_FINALIZED);
    }

    private String formatStrLocaleSafe(String format, Object... args) {
        return String.format((Locale)null, format, args);
    }

    // Used to store the CBC cipher context.
    @DoNotStrip
    private int mCtxPtr;

    // The integer value representing failure in JNI world.
    private static native int nativeFailure();

    private native int nativeEncryptInit(byte[] key, byte[] iv);
    private native int nativeDecryptInit(byte[] key, byte[] iv);

    private native int nativeEncryptUpdate(byte[] data, int offset, int dataLen, byte[] output);
    private native int nativeDecryptUpdate(byte[] data, int offset, int dataLen, byte[] output);

    private native int nativeEncryptFinal(byte[] data, int offset);
    private native int nativeDecryptFinal(byte[] data);

    private native int nativeDestroy();

    private native int nativeGetCipherBlockSize();
}

