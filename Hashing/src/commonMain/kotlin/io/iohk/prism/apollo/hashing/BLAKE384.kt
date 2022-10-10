package io.iohk.prism.apollo.hashing

import io.iohk.prism.apollo.hashing.internal.HashingBase
import io.iohk.prism.apollo.hashing.internal.MathHelper
import kotlin.experimental.or

final class BLAKE384 : HashingBase() {
    private var h0: Long = 0
    private var h1: Long = 0
    private var h2: Long = 0
    private var h3: Long = 0
    private var h4: Long = 0
    private var h5: Long = 0
    private var h6: Long = 0
    private var h7: Long = 0
    private var s0: Long = 0
    private var s1: Long = 0
    private var s2: Long = 0
    private var s3: Long = 0
    private var t0: Long = 0
    private var t1: Long = 0
    private lateinit var tmpM: LongArray
    private lateinit var tmpBuf: ByteArray
    private val initVal: LongArray
        get() = longArrayOf(
            -0x344462a23efa6128L,
            0x629A292A367CD507L,
            -0x6ea6fea5cf8f22e9L,
            0x152FECD8F70E5939L,
            0x67332667FFC00B31L,
            -0x714bb57897a7eaefL,
            -0x24f3d1f29b067059L,
            0x47B5481DBEFA4FA4L
        )
    override val digestLength: Int
        get() = 48
    override val blockLength: Int
        get() = 128

    override fun doInit() {
        tmpM = LongArray(16)
        tmpBuf = ByteArray(128)
        engineReset()
    }

    override fun engineReset() {
        val iv = initVal
        h0 = iv[0]
        h1 = iv[1]
        h2 = iv[2]
        h3 = iv[3]
        h4 = iv[4]
        h5 = iv[5]
        h6 = iv[6]
        h7 = iv[7]
        s3 = 0
        s2 = s3
        s1 = s2
        s0 = s1
        t1 = 0
        t0 = t1
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        val ptr = flush()
        val bitLen = ptr shl 3
        val th = t1
        val tl = t0 + bitLen
        tmpBuf[ptr] = 0x80.toByte()
        if (ptr == 0) {
            t0 = -0x400L
            t1 = -0x1L
        } else if (t0 == 0L) {
            t0 = ((-0x400L).toInt() + bitLen).toLong()
            t1--
        } else {
            t0 -= (1024 - bitLen).toLong()
        }
        if (ptr < 112) {
            for (i in ptr + 1..111) tmpBuf[i] = 0x00
            if (digestLength == 64) tmpBuf[111] = tmpBuf[111] or 0x01
            MathHelper.encodeBELong(th, tmpBuf, 112)
            MathHelper.encodeBELong(tl, tmpBuf, 120)
            update(tmpBuf, ptr, 128 - ptr)
        } else {
            for (i in ptr + 1..127) tmpBuf[i] = 0
            update(tmpBuf, ptr, 128 - ptr)
            t0 = -0x400L
            t1 = -0x1L
            for (i in 0..111) tmpBuf[i] = 0x00
            if (digestLength == 64) tmpBuf[111] = 0x01
            MathHelper.encodeBELong(th, tmpBuf, 112)
            MathHelper.encodeBELong(tl, tmpBuf, 120)
            update(tmpBuf, 0, 128)
        }
        MathHelper.encodeBELong(h0, output, outputOffset + 0)
        MathHelper.encodeBELong(h1, output, outputOffset + 8)
        MathHelper.encodeBELong(h2, output, outputOffset + 16)
        MathHelper.encodeBELong(h3, output, outputOffset + 24)
        MathHelper.encodeBELong(h4, output, outputOffset + 32)
        MathHelper.encodeBELong(h5, output, outputOffset + 40)
        if (digestLength == 64) {
            MathHelper.encodeBELong(h6, output, outputOffset + 48)
            MathHelper.encodeBELong(h7, output, outputOffset + 56)
        }
    }

    override fun processBlock(data: ByteArray) {
        t0 += 1024
        if (t0 and 0x3FF.inv() == 0L) t1++
        var v0 = h0
        var v1 = h1
        var v2 = h2
        var v3 = h3
        var v4 = h4
        var v5 = h5
        var v6 = h6
        var v7 = h7
        var v8 = s0 xor 0x243F6A8885A308D3L
        var v9 = s1 xor 0x13198A2E03707344L
        var vA = s2 xor -0x5bf6c7ddd660ce30L
        var vB = s3 xor 0x082EFA98EC4E6C89L
        var vC = t0 xor 0x452821E638D01377L
        var vD = t0 xor -0x41ab9930cb16f394L
        var vE = t1 xor -0x3f53d6483683af23L
        var vF = t1 xor 0x3F84D5B5B5470917L
        val m = tmpM
        for (i in 0..15) m[i] = MathHelper.decodeBELong(data, 8 * i)
        for (r in 0..15) {
            var o0 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x0]
            var o1 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x1]
            v0 += v4 + (m[o0] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o1])
            vC = MathHelper.circularRightLong(vC xor v0, 32)
            v8 += vC
            v4 = MathHelper.circularRightLong(v4 xor v8, 25)
            v0 += v4 + (m[o1] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o0])
            vC = MathHelper.circularRightLong(vC xor v0, 16)
            v8 += vC
            v4 = MathHelper.circularRightLong(v4 xor v8, 11)
            o0 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x2]
            o1 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x3]
            v1 += v5 + (m[o0] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o1])
            vD = MathHelper.circularRightLong(vD xor v1, 32)
            v9 += vD
            v5 = MathHelper.circularRightLong(v5 xor v9, 25)
            v1 += v5 + (m[o1] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o0])
            vD = MathHelper.circularRightLong(vD xor v1, 16)
            v9 += vD
            v5 = MathHelper.circularRightLong(v5 xor v9, 11)
            o0 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x4]
            o1 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x5]
            v2 += v6 + (m[o0] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o1])
            vE = MathHelper.circularRightLong(vE xor v2, 32)
            vA += vE
            v6 = MathHelper.circularRightLong(v6 xor vA, 25)
            v2 += v6 + (m[o1] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o0])
            vE = MathHelper.circularRightLong(vE xor v2, 16)
            vA += vE
            v6 = MathHelper.circularRightLong(v6 xor vA, 11)
            o0 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x6]
            o1 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x7]
            v3 += v7 + (m[o0] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o1])
            vF = MathHelper.circularRightLong(vF xor v3, 32)
            vB += vF
            v7 = MathHelper.circularRightLong(v7 xor vB, 25)
            v3 += v7 + (m[o1] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o0])
            vF = MathHelper.circularRightLong(vF xor v3, 16)
            vB += vF
            v7 = MathHelper.circularRightLong(v7 xor vB, 11)
            o0 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x8]
            o1 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0x9]
            v0 += v5 + (m[o0] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o1])
            vF = MathHelper.circularRightLong(vF xor v0, 32)
            vA += vF
            v5 = MathHelper.circularRightLong(v5 xor vA, 25)
            v0 += v5 + (m[o1] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o0])
            vF = MathHelper.circularRightLong(vF xor v0, 16)
            vA += vF
            v5 = MathHelper.circularRightLong(v5 xor vA, 11)
            o0 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0xA]
            o1 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0xB]
            v1 += v6 + (m[o0] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o1])
            vC = MathHelper.circularRightLong(vC xor v1, 32)
            vB += vC
            v6 = MathHelper.circularRightLong(v6 xor vB, 25)
            v1 += v6 + (m[o1] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o0])
            vC = MathHelper.circularRightLong(vC xor v1, 16)
            vB += vC
            v6 = MathHelper.circularRightLong(v6 xor vB, 11)
            o0 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0xC]
            o1 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0xD]
            v2 += v7 + (m[o0] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o1])
            vD = MathHelper.circularRightLong(vD xor v2, 32)
            v8 += vD
            v7 = MathHelper.circularRightLong(v7 xor v8, 25)
            v2 += v7 + (m[o1] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o0])
            vD = MathHelper.circularRightLong(vD xor v2, 16)
            v8 += vD
            v7 = MathHelper.circularRightLong(v7 xor v8, 11)
            o0 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0xE]
            o1 = io.iohk.prism.apollo.hashing.BLAKE384.Companion.SIGMA[(r shl 4) + 0xF]
            v3 += v4 + (m[o0] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o1])
            vE = MathHelper.circularRightLong(vE xor v3, 32)
            v9 += vE
            v4 = MathHelper.circularRightLong(v4 xor v9, 25)
            v3 += v4 + (m[o1] xor io.iohk.prism.apollo.hashing.BLAKE384.Companion.CB[o0])
            vE = MathHelper.circularRightLong(vE xor v3, 16)
            v9 += vE
            v4 = MathHelper.circularRightLong(v4 xor v9, 11)
        }
        h0 = h0 xor (s0 xor v0 xor v8)
        h1 = h1 xor (s1 xor v1 xor v9)
        h2 = h2 xor (s2 xor v2 xor vA)
        h3 = h3 xor (s3 xor v3 xor vB)
        h4 = h4 xor (s0 xor v4 xor vC)
        h5 = h5 xor (s1 xor v5 xor vD)
        h6 = h6 xor (s2 xor v6 xor vE)
        h7 = h7 xor (s3 xor v7 xor vF)
    }

    override fun toString() = "BLAKE-384"

    companion object {
        private val SIGMA = intArrayOf(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
            9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
            2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
            12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
            13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
            6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
            10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
            11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
            7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
            9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
            2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9
        )
        private val CB = longArrayOf(
            0x243F6A8885A308D3L, 0x13198A2E03707344L,
            -0x5bf6c7ddd660ce30L, 0x082EFA98EC4E6C89L,
            0x452821E638D01377L, -0x41ab9930cb16f394L,
            -0x3f53d6483683af23L, 0x3F84D5B5B5470917L,
            -0x6de92a26768604e5L, -0x2ecef45967204a54L,
            0x2FFD72DBD01ADFB7L, -0x471e501295d9816aL,
            -0x45836fba0ed38067L, 0x24A19947B3916CF7L,
            0x0801F2E2858EFC16L, 0x636920D871574E69L
        )
    }
}