package org.hyperledger.identus.apollo.threshold_ecdsa.tuple

/**
 * A data class representing a sextuple, which holds six values of potentially different types.
 *
 * @param first The first value of type A.
 * @param second The second value of type B.
 * @param third The third value of type C.
 * @param fourth The fourth value of type D.
 * @param fifth The fifth value of type E.
 * @param sixth The sixth value of type F.
 */
data class Sextuple<A, B, C, D, E, F>(
    val first: A,
    val second: B,
    val third: C,
    val fourth: D,
    val fifth: E,
    val sixth: F
)

/**
 * A data class representing a septuple, which holds seven values of potentially different types.
 *
 * @param first The first value of type A.
 * @param second The second value of type B.
 * @param third The third value of type C.
 * @param fourth The fourth value of type D.
 * @param fifth The fifth value of type E.
 * @param sixth The sixth value of type F.
 * @param seventh The seventh value of type G.
 */
data class Septuple<A, B, C, D, E, F, G>(
    val first: A,
    val second: B,
    val third: C,
    val fourth: D,
    val fifth: E,
    val sixth: F,
    val seventh: G
)

/**
 * A data class representing a quintuple, which holds five values of potentially different types.
 *
 * @param first The first value of type A.
 * @param second The second value of type B.
 * @param third The third value of type C.
 * @param fourth The fourth value of type D.
 * @param fifth The fifth value of type E.
 */
data class Quintuple<A, B, C, D, E>(
    val first: A,
    val second: B,
    val third: C,
    val fourth: D,
    val fifth: E
)