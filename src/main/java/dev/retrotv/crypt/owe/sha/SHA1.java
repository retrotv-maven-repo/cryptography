package dev.retrotv.crypt.owe.sha;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.OneWayEncryption;

public class SHA1 extends SHA implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        return encode(Algorithm.SHA1, data);
    }
}
