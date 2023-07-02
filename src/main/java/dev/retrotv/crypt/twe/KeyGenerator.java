package dev.retrotv.crypt.twe;

import dev.retrotv.crypt.exception.KeyGenerateException;

import java.security.Key;

public interface KeyGenerator  {
    Key generateKey() throws KeyGenerateException;
}
