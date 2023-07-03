package dev.retrotv.crypt.twe.lea;

import dev.retrotv.enums.Algorithm;

public class LEACTR192 extends LEACTR {

    public LEACTR192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.LEACTR192_NO_PADDING;
    }
}
