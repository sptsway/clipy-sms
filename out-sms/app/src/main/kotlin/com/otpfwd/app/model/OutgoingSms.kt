package com.otpfwd.app.model

import com.otpfwd.app.json.Json
import java.nio.charset.StandardCharsets

/** The plaintext forwarded to the Mac (PROTOCOL.md §4.3), encrypted verbatim as the envelope's
 * ciphertext. `sim` is omitted from the JSON entirely on single-SIM phones or whenever slot
 * extraction fails (DESIGN.md §7), never sent as an explicit `null`. */
data class OutgoingSms(
    val id: String,
    val tsMs: Long,
    val ctr: Long,
    val sender: String,
    val body: String,
    val sim: Int?,
) {
    fun toJsonBytes(): ByteArray {
        val obj = Json.obj()
            .put("id", id)
            .put("ts", tsMs)
            .put("ctr", ctr)
            .put("sender", sender)
            .put("body", body)
        if (sim != null) obj.put("sim", sim.toLong())
        return Json.write(obj).toByteArray(StandardCharsets.UTF_8)
    }
}
