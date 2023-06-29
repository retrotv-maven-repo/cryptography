package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESCBC256 extends AESCBC {
    public AESCBC256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.AESCBC256_PADDING;
    }
}
