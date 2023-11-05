package dev.retrotv.common

import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.*
import java.util.logging.Formatter
import java.util.logging.Handler
import java.util.logging.LogRecord

class LogFormatter : Formatter() {
    override fun format(record: LogRecord): String {
        val builder = StringBuilder(1000)
        builder.append(df.format(Date(record.millis))).append(" - ")
        builder.append("[").append(record.getSourceClassName()).append(".")
        builder.append(record.getSourceMethodName()).append("] - ")
        builder.append("[").append(record.level).append("] - ")
        builder.append(formatMessage(record))
        builder.append("\n")
        return builder.toString()
    }

    override fun getHead(h: Handler): String {
        return super.getHead(h)
    }

    override fun getTail(h: Handler): String {
        return super.getTail(h)
    }

    companion object {
        private val df: DateFormat = SimpleDateFormat("dd/MM/yyyy hh:mm:ss.SSS")
    }
}
