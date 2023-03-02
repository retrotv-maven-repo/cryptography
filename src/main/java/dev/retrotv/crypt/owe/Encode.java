package dev.retrotv.crypt.owe;

import dev.retrotv.crypt.Algorithm;
import dev.retrotv.crypt.exception.CryptFailException;

import javax.xml.bind.DatatypeConverter;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.zip.CRC32;

/**
 * {@link MessageDigest}를 사용하는 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author yjj8353
 * @since 1.8
 */
public class Encode {

    /**
     * 지정된 {@link Algorithm} 유형으로 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @param algorithm 암호화 시, 사용할 알고리즘
     * @param data      암호화 할 데이터
     * @return 암호화 된 데이터
     * @throws CryptFailException data가 null 일 경우 발생
     * @throws CryptFailException 암호화가 정상적으로 진행되지 않았을 경우 발생
     */
    protected byte[] encode(Algorithm algorithm, byte[] data) {
        Optional.ofNullable(data).orElseThrow(() ->
                new CryptFailException("암호화 할 문자열 및 데이터는 null 일 수 없습니다."));

        // CRC-32 알고리즘은 MessageDigest를 쓰지 않으므로 별도로 분리
        if (Algorithm.CRC32.equals(algorithm)) {
            return crc32Encode(data);
        }

        try {
            MessageDigest md = MessageDigest.getInstance(algorithm.label());
            md.update(data);

            return md.digest();
        } catch (NoSuchAlgorithmException ignored) { }

        throw new CryptFailException("암호화가 정상적으로 진행되지 않았습니다.");
    }

    private byte[] crc32Encode(byte[] data) {
        CRC32 crc32 = new CRC32();
        crc32.update(data);

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(crc32.getValue());

        // 앞에 0이 패딩되는 부분을 무시하고 뒤의 8자리만 잘라낸다
        return DatatypeConverter.parseHexBinary(
                DatatypeConverter.printHexBinary(buffer.array()).substring(8));
    }
}
