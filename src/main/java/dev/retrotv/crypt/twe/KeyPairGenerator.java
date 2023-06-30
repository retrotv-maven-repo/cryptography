package dev.retrotv.crypt.twe;

import java.security.KeyPair;

import dev.retrotv.crypt.exception.KeyGenerateException;

public interface KeyPairGenerator {
    public KeyPair generateKeyPair() throws KeyGenerateException;
}
