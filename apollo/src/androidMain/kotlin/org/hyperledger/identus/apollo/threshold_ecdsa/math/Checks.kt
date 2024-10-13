package org.hyperledger.identus.apollo.threshold_ecdsa.math

import java.math.BigInteger

/**
 * Checks if the provided integers are all in the range [1, ..., N-1] and are co-prime to N.
 *
 * @param N The modulus to which the integers should be co-prime.
 * @param ints The integers to check.
 * @return `true` if all integers are in the valid range and co-prime to N; `false` otherwise.
 */

fun isValidModN(N: BigInteger, vararg ints: BigInteger?): Boolean {
    val one = BigInteger.ONE
    for (i in ints) {
        if (i == null) {
            return false
        }
        if (i.signum() != 1) {
            return false
        }
        if (i >= N) {
            return false
        }
        val gcd = i.gcd(N)
        if (gcd != one) {
            return false
        }
    }
    return true
}

/**
 * Returns `true` if n ∈ [-2ˡ⁺ᵉ, ..., 2ˡ⁺ᵉ].
 *
 * @param n The number to check.
 * @return `true` if n is within the specified interval; `false` otherwise.
 */
fun isInIntervalLEps(n: BigInteger): Boolean {
    return n.bitLength() <= LPlusEpsilon
}

/**
 * Returns `true` if n ∈ [-2ˡ'⁺ᵉ, ..., 2ˡ'⁺ᵉ].
 *
 * @param n The number to check.
 * @return `true` if n is within the specified interval; `false` otherwise.
 */
fun isInIntervalLPrimeEps(n: BigInteger): Boolean {
    return n.bitLength() <= LPrimePlusEpsilon
}
