package com.facebook.crypto.cipher;

import java.io.IOException;

/**
 * Base exception class for all CBC cipher operations
 */
public class NativeCBCCipherException extends IOException {
    public NativeCBCCipherException(String message) {
        super(message);
    }
}
