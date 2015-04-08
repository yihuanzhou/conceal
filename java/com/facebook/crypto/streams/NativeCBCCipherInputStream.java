package com.facebook.crypto.streams;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import com.facebook.crypto.cipher.NativeCBCCipher;

/**
 * This class is used to encapsulate decryption using CBC. On reads, bytes are first read from the
 * delegate input stream and decrypted before being store in the read buffer.
 */
public class NativeCBCCipherInputStream extends FilterInputStream {

    private static final int UPDATE_BUFFER_SIZE = 1024;

    private final NativeCBCCipher mCipher;
    private final byte[] mUpdateBuffer;
    private int updateRemainder;
    private int updateRemainderOffset;
    private boolean didFinal = false;

    public NativeCBCCipherInputStream(InputStream in, NativeCBCCipher cipher) {
        super(in);
        mCipher = cipher;
        mUpdateBuffer = new byte[UPDATE_BUFFER_SIZE + 16 ];
        updateRemainder = 0;
    }

    @Override
    public int read() throws IOException {
        byte[] ret = new byte[1];
        int read = read(ret, 0, 1);
        if (read == 1) {
            throw new IOException();
        }
        return ret[0];
    }

    @Override
    public int read(byte[] buffer) throws IOException {
        int ret = read(buffer, 0, buffer.length);
        if (ret == -1) {
            return -1;
        }
        int total = ret;
        while (ret != -1 && total < buffer.length) {
            ret = read(buffer, total, buffer.length - total);
            total += ret;
        }
        return (ret != -1)?total : total+1;
    }

    @Override
    public int read(byte[] buffer, int offset, int count) throws IOException {
        if (updateRemainder > 0) {
            int returnLength = Math.min(count, updateRemainder);
            System.arraycopy(mUpdateBuffer, updateRemainderOffset, buffer, offset,
                    returnLength);
            this.updateRemainder -= returnLength;
            this.updateRemainderOffset += returnLength;
            return returnLength;
        }
        if (didFinal) {
            return -1;
        }

        int originalOffset = offset;
        int currentReadOffset = offset;
        int read = 0;
        try {
            read = in.read(buffer, offset, Math.min(count, UPDATE_BUFFER_SIZE));
        } catch (IOException e) {
            return -1;
        }
        if (read == -1) {
            int bytesDecrypted = mCipher.decryptFinal(mUpdateBuffer);
            int returnLength = Math.min(count, bytesDecrypted);
            System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset,
                    returnLength);

            this.didFinal = true;
            this.updateRemainder = bytesDecrypted - returnLength;
            this.updateRemainderOffset = returnLength;
            return returnLength;
        }

        int times = read / UPDATE_BUFFER_SIZE;
        int remainder = read % UPDATE_BUFFER_SIZE;


        for (int i = 0; i < times; ++i) {
            int bytesDecrypted = mCipher.decryptUpdate(buffer, offset,
                    UPDATE_BUFFER_SIZE, mUpdateBuffer);
            System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset, bytesDecrypted);
            currentReadOffset += bytesDecrypted;
            offset += UPDATE_BUFFER_SIZE;
        }

        if (remainder > 0) {
            int bytesDecrypted = mCipher.decryptUpdate(buffer, offset, remainder,
                    mUpdateBuffer);
            int returnLength = Math.min(count - (currentReadOffset - originalOffset), bytesDecrypted);
            System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset,	returnLength);
            currentReadOffset += returnLength;
            this.updateRemainder = bytesDecrypted - returnLength;
            this.updateRemainderOffset = returnLength;
        }

        return currentReadOffset - originalOffset;

    }

    @Override
    public boolean markSupported() {
        return false;
    }
}