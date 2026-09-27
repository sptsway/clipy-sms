package com.otpfwd.app.json

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class JsonTest {

    @Test
    fun `round trips strings, numbers, negative numbers, and string lists`() {
        val obj = Json.obj()
            .put("s", "hello \"world\"\nwith\\backslash and unicode: é中文")
            .put("n", 12345L)
            .put("neg", -7L)
            .put("list", listOf("a", "b", "c"))

        val parsed = Json.parseObj(Json.write(obj))

        assertEquals(obj.getString("s"), parsed.getString("s"))
        assertEquals(obj.getLong("n"), parsed.getLong("n"))
        assertEquals(obj.getLong("neg"), parsed.getLong("neg"))
        assertEquals(obj.getStringList("list"), parsed.getStringList("list"))
    }

    @Test
    fun `nullable long round trips both present and absent`() {
        val obj = Json.obj()
            .putNullableLong("present", 42L)
            .putNullableLong("absent", null)

        val parsed = Json.parseObj(Json.write(obj))

        assertEquals(42L, parsed.getNullableLong("present"))
        assertEquals(null, parsed.getNullableLong("absent"))
    }

    @Test
    fun `empty string list round trips`() {
        val obj = Json.obj().put("empty", emptyList<String>())
        val parsed = Json.parseObj(Json.write(obj))
        assertTrue(parsed.getStringList("empty").isEmpty())
    }

    @Test
    fun `device name with spaces and apostrophes round trips`() {
        val obj = Json.obj().put("device_name", "Swaraj's MacBook Pro")
        val parsed = Json.parseObj(Json.write(obj))
        assertEquals("Swaraj's MacBook Pro", parsed.getString("device_name"))
    }

    @Test
    fun `nested field order is preserved on write`() {
        val obj = Json.obj().put("z", "1").put("a", "2").put("m", "3")
        val text = Json.write(obj)
        assertTrue(text.indexOf("\"z\"") < text.indexOf("\"a\""))
        assertTrue(text.indexOf("\"a\"") < text.indexOf("\"m\""))
    }
}
