package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAGCM256 extends LEAGCM {

    public LEAGCM256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.LEAGCM256_NO_PADDING;
    }
}
