package dev.retrotv.crypto.cipher.stream;

import dev.retrotv.crypto.cipher.TwoWayEncryption;
import dev.retrotv.crypto.cipher.param.Param;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class StreamCipher implements TwoWayEncryption {
    protected org.bouncycastle.crypto.StreamCipher engine;

    public abstract void encrypt(InputStream input, OutputStream output, Param params);
    public abstract void decrypt(InputStream input, OutputStream output, Param params);
}