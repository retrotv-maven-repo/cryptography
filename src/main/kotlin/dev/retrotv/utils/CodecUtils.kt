@file:JvmName("CodecUtils")
package dev.retrotv.utils

import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.enums.EncodeFormat.*
import dev.retrotv.data.utils.ByteUtils
import dev.retrotv.data.utils.StringUtils
import org.apache.commons.codec.DecoderException

fun encode(format: EncodeFormat, data: ByteArray): String {
    return when (format) {
        HEX -> ByteUtils.toHexString(data)
        BASE64 -> ByteUtils.toBase64String(data)
    }
}

@Throws(DecoderException::class)
fun decode(format: EncodeFormat, encodedData: String): ByteArray {
    return when (format) {
        HEX -> StringUtils.hexStringToByteArray(encodedData)
        BASE64 -> StringUtils.base64StringToByteArray(encodedData)
    }
}