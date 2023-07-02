package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.enums.Algorithm;

import javax.crypto.spec.IvParameterSpec;

public class AESCFB192 extends AESCFB {

    public AESCFB192() {
        this.keyLength = 24;
        this.algorithm = Algorithm.AESCFB192_NO_PADDING;
    }
}
