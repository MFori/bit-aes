package cz.martinforejt.bit.aes

import java.io.File

/**
 * Params holder
 *
 * Created by Martin Forejt on 10.05.2020.
 * me@martinforejt.cz
 *
 * @author Martin Forejt
 */
@Suppress("ArrayInDataClass")
data class Params(
    /**
     * Input, plain text or cypher text
     */
    val text: ByteArray,
    /**
     * Key
     */
    val key: String,
    /**
     * Mode
     */
    val mode: Mode,
    /**
     * Output file
     */
    val out: File?,
    /**
     * Raw output? or hex format
     */
    val raw: Boolean
)