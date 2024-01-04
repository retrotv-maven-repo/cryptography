@file:JvmName("EncodeUtils")
package dev.retrotv.utils

import dev.retrotv.data.enums.EncodeFormat
import dev.retrotv.data.enums.EncodeFormat.*
import dev.retrotv.data.utils.base64StringToByteArray
import dev.retrotv.data.utils.hexStringToByteArray
import dev.retrotv.data.utils.toBase64String
import dev.retrotv.data.utils.toHexString
import org.apache.commons.codec.DecoderException

fun encode(format: EncodeFormat, data: ByteArray): String {
    return when (format) {
        HEX -> toHexString(data)
        BASE64 -> toBase64String(data)
    }
}

@Throws(DecoderException::class)
fun decode(format: EncodeFormat, encodedData: String): ByteArray {
    return when (format) {
        HEX -> hexStringToByteArray(encodedData)
        BASE64 -> base64StringToByteArray(encodedData)
    }
}