package dev.retrotv.crypt.twe;

import dev.retrotv.crypt.exception.KeyGenerateException;

public interface KeyGenerator  {
    public byte[] generateKey() throws KeyGenerateException;
}
