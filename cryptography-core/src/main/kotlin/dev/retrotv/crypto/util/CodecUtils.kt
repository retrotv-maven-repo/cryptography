package dev.retrotv.crypto.util

import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.enums.EncodeFormat.*
import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.data.utils.StringUtils
import org.apache.commons.codec.DecoderException

/**
 * 데이터를 인코딩 및 디코딩 하는 유틸리티 클래스 입니다.
 */
object CodecUtils {

    /**
     * 데이터를 인코딩합니다.
     *
     * @param data 인코딩할 데이터
     * @param format 인코딩 포맷 (기본값: HEX)
     * @return 인코딩된 데이터
     */
    @JvmStatic
    @JvmOverloads
    fun encode(data: ByteArray, format: EncodeFormat = HEX): String {
        return when (format) {
            HEX -> ByteUtils.toHexString(data)
            BASE64 -> ByteUtils.toBase64String(data)
        }
    }

    /**
     * 데이터를 디코딩합니다.
     *
     * @param encodedData 디코딩할 데이터
     * @param format 디코딩 포맷 (기본값: HEX)
     * @return 디코딩된 데이터
     * @throws DecoderException 디코딩 과정에서 오류가 발생할 경우 던짐
     */
    @JvmStatic
    @JvmOverloads
    @Throws(DecoderException::class)
    fun decode(encodedData: String, format: EncodeFormat = HEX): ByteArray {
        return when (format) {
            HEX -> StringUtils.hexToByteArray(encodedData)
            BASE64 -> StringUtils.base64ToByteArray(encodedData)
        }
    }
}