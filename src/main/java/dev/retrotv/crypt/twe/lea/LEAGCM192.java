package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAGCM192 extends LEAGCM {

    public LEAGCM192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.LEAGCM192_NO_PADDING;
    }
}
