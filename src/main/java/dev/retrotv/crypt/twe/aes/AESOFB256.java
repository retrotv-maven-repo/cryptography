package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESOFB256 extends AESOFB {

    public AESOFB256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.AESOFB256_NO_PADDING;
    }
}
