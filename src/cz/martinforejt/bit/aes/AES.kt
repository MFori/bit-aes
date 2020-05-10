package cz.martinforejt.bit.aes

import java.io.ByteArrayOutputStream
import java.util.*

/**
 * Created by Martin Forejt on 10.05.2020.
 * me@martinforejt.cz
 *
 * @author Martin Forejt
 */
class AES private constructor(
    private val mode: Mode,
    private val key: ByteArray,
    private val iv: ByteArray?
) {

    /**
     * state 4x4 matrix
     * see: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
     */
    private val state = Array(4) { IntArray(4) { 0 } }
    /**
     * r - the number of transformation rounds that convert the input, called the plaintext, into the final output, called
     * the ciphertext. The number of rounds are as follows:
     * 10 rounds for 128-bit keys.
     * 12 rounds for 192-bit keys.
     * 14 rounds for 256-bit keys.
     * see: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
     */
    private val r: Int
    /**
     * n - the length of the key in 32-bit words: 4 words for AES-128, 6 words for AES-192, and 8 words for AES-256
     * see: https://en.wikipedia.org/wiki/AES_key_schedule
     */
    private val n: Int
    /**
     * w - the 32-bit words of the expanded key
     * see: https://en.wikipedia.org/wiki/AES_key_schedule
     */
    private val w: IntArray
    /**
     * The Rijndael S-box, a substitution box (lookup table) used in the Rijndael cipher,
     * which the Advanced Encryption Standard (AES) cryptographic algorithm is based on.
     */
    private val sBox = intArrayOf(
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    )
    /**
     * The round constant rconi for round i of the key expansion is the 32-bit word
     * rcon-i = [rc-i, 0x00, 0x00, 0x00]
     * rc-i table: https://en.wikipedia.org/wiki/AES_key_schedule
     */
    private val rCon = arrayOf(
        intArrayOf(0x00, 0x00, 0x00, 0x00),
        intArrayOf(0x01, 0x00, 0x00, 0x00),
        intArrayOf(0x02, 0x00, 0x00, 0x00),
        intArrayOf(0x04, 0x00, 0x00, 0x00),
        intArrayOf(0x08, 0x00, 0x00, 0x00),
        intArrayOf(0x10, 0x00, 0x00, 0x00),
        intArrayOf(0x20, 0x00, 0x00, 0x00),
        intArrayOf(0x40, 0x00, 0x00, 0x00),
        intArrayOf(0x80, 0x00, 0x00, 0x00),
        intArrayOf(0x1b, 0x00, 0x00, 0x00),
        intArrayOf(0x36, 0x00, 0x00, 0x00)
    )

    companion object {
        /**
         * size of state matrix (4x4)
         */
        private const val STATE_SIZE = 4

        fun encrypt(mode: Mode, text: ByteArray, key: ByteArray, iv: ByteArray? = null): ByteArray {
            val aes = AES(mode, key, iv)
            return aes.encrypt(text)
        }

        fun decrypt(mode: Mode, text: ByteArray, key: ByteArray, iv: ByteArray? = null): ByteArray {
            val aes = AES(mode, key, iv)
            return aes.decrypt(text)
        }
    }

    init {
        when (key.size) {
            16 -> {
                r = 10
                n = 4
            }
            24 -> {
                r = 12
                n = 6
            }
            32 -> {
                r = 14
                n = 8
            }
            else -> {
                throw IllegalArgumentException("Illegal key size!")
            }
        }
        w = IntArray(4 * (r + 1))
    }

    private fun encrypt(text: ByteArray): ByteArray {
        keyExpansion()
        return if (mode == Mode.ECB) encryptECB(text) else encryptCBC(text)
    }

    private fun decrypt(text: ByteArray): ByteArray {
        keyExpansion()
        return if (mode == Mode.ECB) decryptECB(text) else decryptCBC(text)
    }

    private fun encryptECB(text: ByteArray): ByteArray {
        val stream = ByteArrayOutputStream()
        for (i in 0 until text.size step 16) {
            stream.write(encryptBlock(Arrays.copyOfRange(text, i, i + 16)))
        }
        return stream.toByteArray()
    }

    private fun encryptCBC(text: ByteArray): ByteArray {
        TODO()
    }

    private fun decryptECB(text: ByteArray): ByteArray {
        val stream = ByteArrayOutputStream()
        for (i in 0 until text.size step 16) {
            stream.write(decryptBlock(text.copyOfRange(i, i + 16)))
        }
        return stream.toByteArray()
    }

    private fun decryptCBC(text: ByteArray): ByteArray {
        TODO()
    }

    private fun encryptBlock(block: ByteArray): ByteArray {
        println("block " + Arrays.toString(block))
        val out = ByteArray(block.size)

        for (i in 0 until STATE_SIZE) {
            for (j in 0 until STATE_SIZE) {
                state[i][j] = block[j * STATE_SIZE + i].toInt() and 0xff
            }
        }

        var round = 0
        addRoundKey(round)
        printState(0)

        round = 1
        while (round < r) {
            subBytes()
            shiftRows()
            mixColumns()
            addRoundKey(round)
            printState(round)
            round++
        }
        printState(-1)
        subBytes()
        shiftRows()
        addRoundKey(round)

        for (i in 0 until STATE_SIZE) {
            for (j in 0 until STATE_SIZE) {
                out[j * STATE_SIZE + i] = (state[i][j] and 0xff).toByte()
            }
        }
        return out
    }

    private fun printState(s: Int) {
        println("state #$s" + Arrays.toString(state[0]) + " , " + Arrays.toString(state[1]))
    }

    private fun decryptBlock(block: ByteArray): ByteArray {
        TODO()
    }

    /**
     * Key expansion:
     * round keys [w] are derived from the cipher key using Rijndael's key schedule and saved to
     */
    private fun keyExpansion() {
        var i = 0
        while (i < n) {
            w[i] = (key[4 * i].toInt() shl 24) or (key[4 * i + 1].toInt() and 0xff shl 16) or (key[4 * i + 2].toInt()
                    and 0xff shl 8) or (key[4 * i + 3].toInt() and 0xff)
            i++
        }
        i = n
        while (i <= 4 * (r + 1) - 1) {
            if (i % n == 0) {
                val rConVal = rCon[i / n][0] shl 24 or (rCon[i / n][1] and 0xff shl 16) or
                        (rCon[i / n][2] and 0xff shl 8) or (rCon[i / n][3] and 0xff)
                w[i] = w[i - n] xor subWord(rotWord(w[i - 1])) xor rConVal
            } else if (n < 6 && (i % n == 4)) {
                w[i] = w[i - n] xor subWord(w[i - 1])
            } else {
                w[i] = w[i - n] xor w[i - 1]
            }
            i++
        }
    }

    /**
     * each byte of the state is combined with a byte of the round key using xor
     *
     * @param round current round, round key is w[round]
     */
    private fun addRoundKey(round: Int) {
        for (i in 0 until STATE_SIZE) {
            for (j in 0 until STATE_SIZE) {
                state[i][j] = state[i][j] xor (w[round * STATE_SIZE + j] shl (i * 8)).ushr(24)
            }
        }
    }

    /**
     * a non-linear substitution step where each byte is replaced with another according to a lookup table
     */
    private fun subBytes() {
        for (i in 0 until STATE_SIZE) {
            for (j in 0 until STATE_SIZE) {
                state[i][j] = subWord(state[i][j]) and 0xff
            }
        }
    }

    /**
     * a transposition step where the last three rows of the state are shifted cyclically a certain number of steps.
     */
    private fun shiftRows() {
        // row 1
        var t1 = state[1][0]
        for (i in 0 until STATE_SIZE) {
            state[1][i] = state[1][(i + 1) % STATE_SIZE]
        }
        state[1][STATE_SIZE - 1] = t1

        // row2
        t1 = state[2][0]
        var t2 = state[2][1]
        for (i in 0 until STATE_SIZE - 1) {
            state[2][i] = state[2][(i + 2) % STATE_SIZE]
        }
        state[2][STATE_SIZE - 2] = t1
        state[2][STATE_SIZE - 1] = t2

        // row3
        t1 = state[3][0]
        t2 = state[3][1]
        val t3 = state[3][2]
        for (i in 0 until STATE_SIZE - 2) {
            state[3][i] = state[3][(i + 3) % STATE_SIZE]
        }
        state[3][STATE_SIZE - 3] = t1
        state[3][STATE_SIZE - 2] = t2
        state[3][STATE_SIZE - 1] = t3
    }

    /**
     * a linear mixing operation which operates on the columns of the state, combining the four bytes in each column.
     */
    private fun mixColumns() {
        for (c in 0 until STATE_SIZE) {
            val t0 = gMul(0x02, state[0][c]) xor gMul(0x03, state[1][c]) xor state[2][c] xor state[3][c]
            val t1 = state[0][c] xor gMul(0x02, state[1][c]) xor gMul(0x03, state[2][c]) xor state[3][c]
            val t2 = state[0][c] xor state[1][c] xor gMul(0x02, state[2][c]) xor gMul(0x03, state[3][c])
            val t3 = gMul(0x03, state[0][c]) xor state[1][c] xor state[2][c] xor gMul(0x02, state[3][c])

            state[0][c] = t0
            state[1][c] = t1
            state[2][c] = t2
            state[3][c] = t3
        }

    }

    /**
     * Multiplies two int in garlois field 2^8
     *
     * @param pa
     * @param pb
     * @return
     */
    private fun gMul(pa: Int, pb: Int): Int {
        var a = pa
        var b = pb
        var res = 0
        var temp: Int
        while (a != 0) {
            if (a and 1 != 0) res = res xor b
            temp = b and 0x80
            b = b shl 1
            if (temp != 0) b = b xor 0x1b
            a = a and 0xff shr 1
        }
        return res
    }

    /**
     * One-byte left circular shift
     *
     * @param word word
     * @return shifted word
     */
    private fun rotWord(word: Int): Int {
        return word shl 8 or (word and -0x1000000).ushr(24)
    }

    /**
     * An application of the AES S-box to each of the four bytes of the word
     *
     * @return
     */
    private fun subWord(word: Int): Int {
        var subWord = 0
        var i = 24
        while (i >= 0) {
            val index = (word shl i).ushr(24)
            subWord = subWord or (sBox[index] shl 24 - i)
            i -= 8
        }
        return subWord
    }
}