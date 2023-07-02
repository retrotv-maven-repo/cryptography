package dev.retrotv.crypt.twe.aes;

import dev.retrotv.crypt.twe.ParameterSpecGenerator;
import dev.retrotv.enums.Algorithm;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.spec.IvParameterSpec;

public class AESCFB128 extends AESCFB {

    public AESCFB128() {
        this.keyLength = 16;
        this.algorithm = Algorithm.AESCFB128_NO_PADDING;
    }
}
