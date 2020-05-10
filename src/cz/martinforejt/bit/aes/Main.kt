package cz.martinforejt.bit.aes

import java.io.*

/**
 * Created by Martin Forejt on 10.05.2020.
 * me@martinforejt.cz
 *
 * @author Martin Forejt
 */

fun main(args: Array<String>) {
    val params = getParams(args) ?: return

    if (params.mode == Mode.ENCRYPT) {
        val res = AES.encrypt(params.text, params.key.toByteArray())
        val out = if (params.out != null) {
            PrintStream(FileOutputStream(params.out))
        } else {
            System.out
        }
        try {
            if (params.raw) {
                out.write(res)
            } else {
                res.forEachIndexed { i, v ->
                    out.print(String.format("%02x ", v))
                    if ((i + 1) % 16 == 0) out.println()
                }
            }
        } catch (e: IOException) {
            println("Cant print result to file!")
        } finally {
            out.close()
        }
    } else {
        val res = AES.decrypt(params.text, params.key.toByteArray())
        val out = if (params.out != null) {
            FileOutputStream(params.out)
        } else {
            System.out
        }
        try {
            out.write(res)
        } catch (e: IOException) {
            println("Cant print result to file!")
        } finally {
            out.close()
        }
    }
}

private fun getParams(args: Array<String>): Params? {
    if (args.size < 3) return badArguments()

    val mode = when (args[0]) {
        "-e" -> Mode.ENCRYPT
        "-d" -> Mode.DECRYPT
        else -> return badArguments()
    }

    val file = args[1] != "-t"

    val key = if (!file) {
        if (args.size < 4) return badArguments()
        else if (!validKey(args[3])) return badArguments()
        else args[3]
    } else {
        if (!validKey(args[2])) return null
        else args[2]
    }

    val text = if (!file) {
        args[2].toByteArray()
    } else {
        val f = File(args[1])
        if (!f.exists() || !f.isFile) {
            println("File ${args[1]} not found.")
            return null
        } else f.readBytes()
    }

    val out = ((file && args.size >= 5 && args[3] == "-o") || !file && args.size >= 6 && args[4] == "-o")
    val outFile: File? = if (out) {
        File(args[if (file) 4 else 5])
    } else {
        null
    }

    val raw = (out && file && args.size == 6 && args[5] == "-r") ||
            (out && !file && args.size == 7 && args[6] == "-r") ||
            (!out && file && args.size == 4 && args[3] == "-r") ||
            (!out && !file && args.size == 5 && args[4] == "-r")

    return Params(
        text = text,
        key = key,
        mode = mode,
        out = outFile,
        raw = raw
    )
}

private fun badArguments(): Params? {
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
    println("Help")
    println("Run with arguments (in this order):")
    println("1. -e for encryption or -d for decryption")
    println("2. -t \"text input\" or \"file name\"")
    println("3. \"key\"")
    println("optional. -o \"output file name\"")
    println("optional. -r for raw output (without -r hex formatted)")
}