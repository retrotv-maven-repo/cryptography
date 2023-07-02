package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESCBC192 extends AESCBC {
    public AESCBC192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.AESCBC192_PADDING;
    }
}
