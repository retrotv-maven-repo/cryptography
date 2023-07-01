package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACBC256 extends LEACBC {

    public LEACBC256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.LEACBC256_PADDING;
    }
}
