package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESOFB192 extends AESOFB {

    public AESOFB192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.AESOFB192_NO_PADDING;
    }
}
