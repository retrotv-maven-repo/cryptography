@file:JvmName("ResourceBundleUtils")
package dev.retrotv.utils

import java.text.MessageFormat
import java.util.*

private val resourceBundle: ResourceBundle =
    ResourceBundle.getBundle("message", Locale.getDefault())

fun getMessage(key: String, vararg words: String): String {
    return MessageFormat.format(resourceBundle.getString(key), *words)
}