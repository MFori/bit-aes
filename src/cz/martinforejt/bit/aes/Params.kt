package cz.martinforejt.bit.aes

/**
 * Created by Martin Forejt on 10.05.2020.
 * me@martinforejt.cz
 *
 * @author Martin Forejt
 */
@Suppress("ArrayInDataClass")
data class Params(
    val text: ByteArray,
    val key: String
)