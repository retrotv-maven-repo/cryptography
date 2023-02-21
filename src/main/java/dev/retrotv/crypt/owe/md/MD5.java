package dev.retrotv.crypt.owe.md;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.OneWayEncryption;

public class MD5 extends MD implements OneWayEncryption {

    @Override
    public byte[] encrypt(byte[] data) {
        return encode(Algorithm.MD5, data);
    }
}
