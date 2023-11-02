package dev.retrotv.crypto.twe.aes;

import dev.retrotv.crypto.exception.WrongKeyLengthException;
import dev.retrotv.crypto.twe.ParameterSpecGenerator;
import dev.retrotv.utils.SecureRandomUtil;

import javax.crypto.spec.IvParameterSpec;

import static dev.retrotv.enums.CipherAlgorithm.AESCBC;

/**
 * AES/CBC 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public class AESCBC extends AES implements ParameterSpecGenerator<IvParameterSpec> {

    public AESCBC(int keyLen) {
        if (keyLen != 128 && keyLen != 192 && keyLen != 256) {
            throw new WrongKeyLengthException();
        }

        this.keyLen = keyLen;
        this.algorithm = AESCBC;
    }

    @Override
    public IvParameterSpec generateSpec() {
        return new IvParameterSpec(SecureRandomUtil.generate(16));
    }
}
