package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESECB192 extends AESECB {

    public AESECB192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.AESECB192_PADDING;
    }
}
