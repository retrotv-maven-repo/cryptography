package dev.retrotv.crypt.twe;

import java.security.PrivateKey;
import java.security.PublicKey;

import dev.retrotv.crypt.exception.CryptFailException;

public interface DigitalSignature {
    
    byte[] sign(byte[] data, PrivateKey privateKey) throws CryptFailException;

    boolean verify(byte[] originalData, byte[] encryptedData, PublicKey publicKey) throws CryptFailException;
}
