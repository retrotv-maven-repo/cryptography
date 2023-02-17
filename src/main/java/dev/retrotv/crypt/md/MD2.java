package dev.retrotv.crypt.md;

import dev.retrotv.crypt.OneWayEncryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class MD2 implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD2");
            md.update(data);
            byte[] encryptedData = md.digest();

            return Base64.getEncoder().encode(encryptedData);
        } catch (NoSuchAlgorithmException ignored) { }

        return null;
    }
}
