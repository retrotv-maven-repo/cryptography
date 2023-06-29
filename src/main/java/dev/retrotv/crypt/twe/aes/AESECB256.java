package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESECB256 extends AESECB {

    public AESECB256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.AESECB256_PADDING;
    }
}
