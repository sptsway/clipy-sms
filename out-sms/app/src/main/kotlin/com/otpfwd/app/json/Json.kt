package com.otpfwd.app.json

/**
 * Minimal JSON codec for this app's own local storage format (`identity.json`) — not a
 * general-purpose/standards-exhaustive parser, just enough to round-trip the value shapes this
 * app actually writes (objects, arrays of strings, strings, integers, booleans, null) with
 * correct string escaping. Deliberately avoids `org.json` (Android-framework-stubbed; throws
 * under a plain `testDebugUnitTest` run unless a Robolectric-style shadow is added — see
 * DESIGN.md §5) and avoids adding a JSON library dependency (kotlinx.serialization, Moshi, Gson)
 * for what's one small, fully-internal, fixed-schema file.
 */
object Json {

    sealed class Value {
        data class Obj(val fields: LinkedHashMap<String, Value> = LinkedHashMap()) : Value() {
            fun put(key: String, value: Value): Obj { fields[key] = value; return this }
            fun put(key: String, value: String): Obj = put(key, Str(value))
            fun put(key: String, value: Long): Obj = put(key, Num(value))
            fun put(key: String, value: List<String>): Obj = put(key, Arr(value.map { Str(it) }))
            fun putNullableLong(key: String, value: Long?): Obj =
                put(key, if (value == null) Null else Num(value))

            fun getString(key: String): String =
                (fields[key] as? Str)?.value ?: error("field '$key' missing or not a string")
            fun getLong(key: String): Long =
                (fields[key] as? Num)?.value ?: error("field '$key' missing or not a number")
            fun getNullableLong(key: String): Long? =
                when (val v = fields[key]) {
                    null, Null -> null
                    is Num -> v.value
                    else -> error("field '$key' is not a number")
                }
            fun getStringList(key: String): List<String> =
                (fields[key] as? Arr)?.items?.map { (it as Str).value }
                    ?: error("field '$key' missing or not an array")
            fun getBool(key: String): Boolean =
                (fields[key] as? Bool)?.value ?: error("field '$key' missing or not a boolean")
            fun getBoolOrNull(key: String): Boolean? = (fields[key] as? Bool)?.value
        }
        data class Arr(val items: List<Value>) : Value()
        data class Str(val value: String) : Value()
        data class Num(val value: Long) : Value()
        data class Bool(val value: Boolean) : Value()
        object Null : Value()
    }

    fun obj(): Value.Obj = Value.Obj()

    fun write(value: Value): String = StringBuilder().also { writeValue(value, it) }.toString()

    private fun writeValue(value: Value, sb: StringBuilder) {
        when (value) {
            is Value.Obj -> {
                sb.append('{')
                value.fields.entries.forEachIndexed { i, (k, v) ->
                    if (i > 0) sb.append(',')
                    writeString(k, sb)
                    sb.append(':')
                    writeValue(v, sb)
                }
                sb.append('}')
            }
            is Value.Arr -> {
                sb.append('[')
                value.items.forEachIndexed { i, v ->
                    if (i > 0) sb.append(',')
                    writeValue(v, sb)
                }
                sb.append(']')
            }
            is Value.Str -> writeString(value.value, sb)
            is Value.Num -> sb.append(value.value)
            is Value.Bool -> sb.append(if (value.value) "true" else "false")
            Value.Null -> sb.append("null")
        }
    }

    private fun writeString(s: String, sb: StringBuilder) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '' -> sb.append("\\f")
                else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        sb.append('"')
    }

    fun parse(text: String): Value {
        val parser = Parser(text)
        val value = parser.parseValue()
        parser.skipWhitespace()
        require(parser.atEnd()) { "trailing data after JSON value at offset ${parser.pos}" }
        return value
    }

    fun parseObj(text: String): Value.Obj = parse(text) as Value.Obj

    private class Parser(val text: String) {
        var pos = 0
        fun atEnd() = pos >= text.length
        fun peek() = text[pos]
        fun skipWhitespace() { while (!atEnd() && peek().isWhitespace()) pos++ }

        fun expect(c: Char) {
            require(!atEnd() && peek() == c) { "expected '$c' at offset $pos" }
            pos++
        }

        fun parseValue(): Value {
            skipWhitespace()
            require(!atEnd()) { "unexpected end of input" }
            return when (peek()) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> Value.Str(parseStringLiteral())
                't' -> { expectLiteral("true"); Value.Bool(true) }
                'f' -> { expectLiteral("false"); Value.Bool(false) }
                'n' -> { expectLiteral("null"); Value.Null }
                else -> parseNumber()
            }
        }

        fun expectLiteral(lit: String) {
            require(text.regionMatches(pos, lit, 0, lit.length)) { "expected '$lit' at offset $pos" }
            pos += lit.length
        }

        fun parseObject(): Value.Obj {
            expect('{')
            val obj = Value.Obj()
            skipWhitespace()
            if (!atEnd() && peek() == '}') { pos++; return obj }
            while (true) {
                skipWhitespace()
                val key = parseStringLiteral()
                skipWhitespace()
                expect(':')
                val value = parseValue()
                obj.fields[key] = value
                skipWhitespace()
                require(!atEnd()) { "unexpected end of input in object" }
                when (peek()) {
                    ',' -> pos++
                    '}' -> { pos++; break }
                    else -> error("expected ',' or '}' at offset $pos")
                }
            }
            return obj
        }

        fun parseArray(): Value.Arr {
            expect('[')
            val items = mutableListOf<Value>()
            skipWhitespace()
            if (!atEnd() && peek() == ']') { pos++; return Value.Arr(items) }
            while (true) {
                items.add(parseValue())
                skipWhitespace()
                require(!atEnd()) { "unexpected end of input in array" }
                when (peek()) {
                    ',' -> pos++
                    ']' -> { pos++; break }
                    else -> error("expected ',' or ']' at offset $pos")
                }
            }
            return Value.Arr(items)
        }

        fun parseStringLiteral(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                require(!atEnd()) { "unterminated string" }
                val c = text[pos++]
                if (c == '"') break
                if (c == '\\') {
                    require(!atEnd()) { "unterminated escape" }
                    when (val e = text[pos++]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('')
                        'u' -> {
                            require(pos + 4 <= text.length) { "truncated \\u escape" }
                            val hex = text.substring(pos, pos + 4)
                            pos += 4
                            sb.append(hex.toInt(16).toChar())
                        }
                        else -> error("invalid escape '\\$e' at offset $pos")
                    }
                } else {
                    sb.append(c)
                }
            }
            return sb.toString()
        }

        fun parseNumber(): Value.Num {
            val start = pos
            if (!atEnd() && peek() == '-') pos++
            while (!atEnd() && peek().isDigit()) pos++
            require(pos > start) { "invalid number at offset $start" }
            return Value.Num(text.substring(start, pos).toLong())
        }
    }
}
