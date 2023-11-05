package dev.retrotv.utils

import dev.retrotv.enums.EncodeFormat
import org.apache.commons.codec.DecoderException
import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.binary.Hex

import dev.retrotv.enums.EncodeFormat.*

class EncodeUtil private constructor() {
    init {
        throw IllegalStateException("유틸리티 클래스 입니다.")
    }

    companion object {
        fun binaryToHex(data: ByteArray?): String {
            requireNotNull(data) { "data는 null일 수 없습니다." }
            return Hex.encodeHexString(data)
        }

        fun binaryToBase64(data: ByteArray?): String {
            requireNotNull(data) { "data는 null일 수 없습니다." }
            return Base64.encodeBase64String(data)
        }

        @Throws(DecoderException::class)
        fun hexToBinary(hex: String?): ByteArray {
            return Hex.decodeHex(hex)
        }

        fun base64ToBinary(base64: String?): ByteArray {
            return Base64.decodeBase64(base64)
        }

        fun binaryEncode(encodeFormat: EncodeFormat?, data: ByteArray?): String {
            var encodeFormat: EncodeFormat? = encodeFormat
            if (encodeFormat == null) {
                encodeFormat = EncodeFormat.HEX
            }
            return when (encodeFormat) {
                BASE64 -> binaryToBase64(data)
                HEX -> binaryToHex(data)
                else -> binaryToHex(data)
            }
        }
    }
}
