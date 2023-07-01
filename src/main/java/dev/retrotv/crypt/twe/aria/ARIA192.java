package dev.retrotv.crypt.twe.aria;

import dev.retrotv.enums.Algorithm;

public class ARIA192 extends ARIA {

    public ARIA192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.ARIA192;
    }
}
