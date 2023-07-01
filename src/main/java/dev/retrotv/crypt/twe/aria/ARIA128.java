package dev.retrotv.crypt.twe.aria;

import dev.retrotv.enums.Algorithm;

public class ARIA128 extends ARIA {
    public ARIA128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.ARIA128;
    }
}
