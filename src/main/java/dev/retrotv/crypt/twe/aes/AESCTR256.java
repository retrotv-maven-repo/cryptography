package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESCTR256 extends AESCTR {

    public AESCTR256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.AESCTR256_NO_PADDING;
    }
}
