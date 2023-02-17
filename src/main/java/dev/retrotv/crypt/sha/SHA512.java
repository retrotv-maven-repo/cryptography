package dev.retrotv.crypt.sha;

import dev.retrotv.crypt.OneWayEncryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512 implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(data);
            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { }

        return null;
    }
}
