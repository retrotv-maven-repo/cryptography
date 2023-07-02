package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESCTR128 extends AESCTR {

    public AESCTR128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.AESCTR128_NO_PADDING;
    }
}
