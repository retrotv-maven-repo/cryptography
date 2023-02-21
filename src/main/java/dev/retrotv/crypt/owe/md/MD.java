package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD {

    protected byte[] encode(Algorithm algorithm, byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm.label());
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { return null; }
    }
}
