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

    @JvmStatic
    @JvmOverloads
    fun encode(data: ByteArray, format: EncodeFormat = BASE64): String {
        return when (format) {
            HEX -> ByteUtils.toHexString(data)
            BASE64 -> ByteUtils.toBase64String(data)
        }
    }

    @JvmStatic
    @JvmOverloads
    @Throws(DecoderException::class)
    fun decode(encodedData: String, format: EncodeFormat = BASE64): ByteArray {
        return when (format) {
            HEX -> StringUtils.hexStringToByteArray(encodedData)
            BASE64 -> StringUtils.base64StringToByteArray(encodedData)
        }
    }
}