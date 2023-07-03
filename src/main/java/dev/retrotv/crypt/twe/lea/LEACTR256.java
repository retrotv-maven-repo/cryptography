package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACTR256 extends LEACTR {

    public LEACTR256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.LEACTR256_NO_PADDING;
    }
}
