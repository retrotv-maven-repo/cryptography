package dev.retrotv.crypt.twe.aes;

import dev.retrotv.enums.Algorithm;

public class AESGCM192 extends AESGCM {
    
    public AESGCM192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.AESGCM192_NO_PADDING;
    }
}
