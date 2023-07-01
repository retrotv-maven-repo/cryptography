package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAGCM128 extends LEAGCM {

    public LEAGCM128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.LEAGCM128_NO_PADDING;
    }
}
