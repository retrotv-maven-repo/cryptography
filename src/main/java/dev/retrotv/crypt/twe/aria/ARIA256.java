package dev.retrotv.crypt.twe.aria;

import dev.retrotv.enums.Algorithm;

public class ARIA256 extends ARIA {

    public ARIA256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.ARIA256;
    }
}
