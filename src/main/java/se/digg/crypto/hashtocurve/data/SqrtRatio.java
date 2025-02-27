package se.digg.crypto.hashtocurve.data;

import java.math.BigInteger;

/**
 * The result of a sqrt_ration calculation
 */
public record SqrtRatio(
    boolean isQR,
    BigInteger ratio
) {
}
