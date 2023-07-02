package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESECB128 extends AESECB {

    public AESECB128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.AESECB128_PADDING;
    }
}
