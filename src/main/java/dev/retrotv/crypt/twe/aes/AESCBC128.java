package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESCBC128 extends AESCBC {
    public AESCBC128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.AESCBC128_PADDING;
    }
}
