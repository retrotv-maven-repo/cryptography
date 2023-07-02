package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESCTR192 extends AESCTR {

    public AESCTR192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.AESCTR192_NO_PADDING;
    }
}
