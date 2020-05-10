package cz.martinforejt.bit.aes

import java.io.File
import java.util.*

/**
 * Created by Martin Forejt on 10.05.2020.
 * me@martinforejt.cz
 *
 * @author Martin Forejt
 */

fun main(args: Array<String>) {
    val params = getParams(args) ?: return
    println(params)

    val aes = cz.martinforejt.bit.aes.old.AES(params.key.toByteArray())
    val res = aes.ECB_encrypt(params.text)

    AES.encrypt(Mode.ECB, "Znám křišťálovou studánku,\nkde nejhlubší je les".toByteArray(), "josefvencasladek".toByteArray())

    res.forEachIndexed { i, v ->
        print(String.format("%02x ", v))
        if ((i + 1) % 16 == 0) println()
    }

}

private fun getParams(args: Array<String>): Params? {
    if (args.size == 3 && args[0] == "-t") {
        if (!validKey(args[2])) return null
        return Params(args[1].toByteArray(), args[2])
    }

    if (args.size == 2) {
        val file = File(args[0])
        if (!file.exists() && !file.isFile) {
            println("File ${args[0]} not found.")
            return null
        }
        if (!validKey(args[1])) return null
        return Params(file.readBytes(), args[1])
    }

    println("Bad arguments!")
    printHelp()
    return null
}

private fun validKey(key: String): Boolean {
    if (key.length != 16 && key.length != 24 && key.length != 32) {
        println("Bad key length. Use 128, 192 or 256 bit key.")
        return false
    }
    return true
}

private fun printHelp() {
    println("todo help")
}