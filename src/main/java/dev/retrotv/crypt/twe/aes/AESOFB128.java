package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESOFB128 extends AESOFB {

    public AESOFB128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.AESOFB128_NO_PADDING;
    }
}
