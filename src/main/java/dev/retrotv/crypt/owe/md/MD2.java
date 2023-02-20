package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.OneWayEncryption;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD2 implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD2");
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { }

        return null;
    }
}
