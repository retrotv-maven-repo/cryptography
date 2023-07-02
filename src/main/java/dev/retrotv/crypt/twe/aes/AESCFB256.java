package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.enums.Algorithm;

import javax.crypto.spec.IvParameterSpec;

public class AESCFB256 extends AESCFB {

    public AESCFB256() {
        this.keyLength = 32;
        this.algorithm = Algorithm.AESCFB256_NO_PADDING;
    }
}
