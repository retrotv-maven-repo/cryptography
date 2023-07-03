package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEAOFB192 extends LEAOFB {

    public LEAOFB192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.LEAOFB192_NO_PADDING;
    }
}
