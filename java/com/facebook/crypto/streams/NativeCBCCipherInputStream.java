package com.facebook.crypto.streams;

import com.facebook.crypto.cipher.NativeCBCCipher;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class is used to encapsulate decryption using CBC. On reads, bytes are first read from the
 * delegate input stream and decrypted before being store in the read buffer.
 */
public class NativeCBCCipherInputStream extends FilterInputStream {

  private static final int UPDATE_BUFFER_SIZE = 1024*8;

  private final NativeCBCCipher mCipher;
  private final byte[] mUpdateBuffer;
  private int mUpdateRemainder;
  private int mUpdateRemainderOffset;
  private boolean mDidFinal = false;

  public NativeCBCCipherInputStream(InputStream in, NativeCBCCipher cipher) {
    super(in);
    mCipher = cipher;
    mUpdateBuffer = new byte[UPDATE_BUFFER_SIZE + mCipher.getCipherBlockSize()];
    mUpdateRemainder = 0;
  }

  @Override
  public void mark(int readlimit) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean markSupported() {
    return false;
  }

  @Override
  public int read() throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public int read(byte[] buffer) throws IOException {
    return read(buffer, 0, buffer.length);
  }

  @Override
  public int read(byte[] buffer, int offset, int length)
      throws IOException {
    if (buffer.length < offset + length) {
      throw new ArrayIndexOutOfBoundsException(offset + length);
    }

    int read = super.read(buffer, offset, length);

    if (read == -1) {// && mDidFinal) {
      return -1;
    } /*else if (!mDidFinal) {
      int bytesDecrypted = mCipher.decryptFinal(mUpdateBuffer);
      System.arraycopy(mUpdateBuffer, 0, buffer, offset, bytesDecrypted);
      mDidFinal = true;
      return bytesDecrypted;
    }*/

    int times = read / UPDATE_BUFFER_SIZE;
    int remainder = read % UPDATE_BUFFER_SIZE;

    int originalOffset = offset;
    int currentReadOffset = offset;

    for (int i = 0; i < times; ++i) {
      int bytesDecrypted = mCipher.decryptUpdate(buffer, offset, UPDATE_BUFFER_SIZE, mUpdateBuffer);
      System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset, bytesDecrypted);
      currentReadOffset += bytesDecrypted;
      offset += UPDATE_BUFFER_SIZE;
    }

    if (remainder > 0) {
      int bytesDecrypted = mCipher.decryptUpdate(buffer, offset, remainder, mUpdateBuffer);
      System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset, bytesDecrypted);
      currentReadOffset += bytesDecrypted;
    }

    return currentReadOffset - originalOffset;
  }

//    @Override
//    public int read(byte[] buffer, int offset, int count) throws IOException {
//        if (mUpdateRemainder > 0) {
//            int returnLength = Math.min(count, mUpdateRemainder);
//            System.arraycopy(mUpdateBuffer, mUpdateRemainderOffset, buffer, offset,
//                    returnLength);
//            mUpdateRemainder -= returnLength;
//            mUpdateRemainderOffset += returnLength;
//            return returnLength;
//        }
//        if (mDidFinal) {
//            return -1;
//        }
//
//        int originalOffset = offset;
//        int currentReadOffset = offset;
//        int read = 0;
//        try {
//            read = in.read(buffer, offset, Math.min(count, UPDATE_BUFFER_SIZE));
//        } catch (IOException e) {
//            return -1;
//        }
//        if (read == -1) {
//            int bytesDecrypted = mCipher.decryptFinal(mUpdateBuffer);
//            int returnLength = Math.min(count, bytesDecrypted);
//            System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset,
//                    returnLength);
//
//            mDidFinal = true;
//            mUpdateRemainder = bytesDecrypted - returnLength;
//            mUpdateRemainderOffset = returnLength;
//            return returnLength;
//        }
//
//        int times = read / UPDATE_BUFFER_SIZE;
//        int remainder = read % UPDATE_BUFFER_SIZE;
//
//
//        for (int i = 0; i < times; ++i) {
//            int bytesDecrypted = mCipher.decryptUpdate(buffer, offset,
//                    UPDATE_BUFFER_SIZE, mUpdateBuffer);
//            System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset, bytesDecrypted);
//            currentReadOffset += bytesDecrypted;
//            offset += UPDATE_BUFFER_SIZE;
//        }
//
//      if (remainder > 0) {
//        int bytesDecrypted = mCipher.decryptUpdate(buffer, offset, remainder,
//            mUpdateBuffer);
//        int returnLength = Math.min(count - (currentReadOffset - originalOffset), bytesDecrypted);
//        System.arraycopy(mUpdateBuffer, 0, buffer, currentReadOffset,	returnLength);
//        currentReadOffset += returnLength;
//        mUpdateRemainder = bytesDecrypted - returnLength;
//        mUpdateRemainderOffset = returnLength;
//      }
//
//      return currentReadOffset - originalOffset;
//
//    }
}