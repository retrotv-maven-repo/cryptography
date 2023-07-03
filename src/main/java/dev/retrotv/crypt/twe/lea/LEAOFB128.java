package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAOFB128 extends LEAOFB {

    public LEAOFB128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.LEAOFB128_NO_PADDING;
    }
}
