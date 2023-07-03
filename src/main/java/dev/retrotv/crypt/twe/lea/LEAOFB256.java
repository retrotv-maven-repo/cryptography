package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAOFB256 extends LEAOFB {

    public LEAOFB256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.LEAOFB256_NO_PADDING;
    }
}
