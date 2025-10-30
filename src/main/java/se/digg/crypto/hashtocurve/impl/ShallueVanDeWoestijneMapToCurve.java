// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.impl;

import java.math.BigInteger;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import se.digg.crypto.hashtocurve.H2cUtils;
import se.digg.crypto.hashtocurve.MapToCurve;
import se.digg.crypto.hashtocurve.SqrtRatioCalculator;
import se.digg.crypto.hashtocurve.data.SqrtRatio;

/**
 * Implements the Shallue van de Woestijne Map to curve according to section 6.6.2 of RFC 9380 This
 * is the straight-line implementation optimized for Weierstrass curves as defined in section F.2.
 */
@SuppressWarnings("checkstyle:MemberName")
public class ShallueVanDeWoestijneMapToCurve implements MapToCurve {

  private final ECParameterSpec ecParameterSpec;
  private final BigInteger z;

  private final SqrtRatioCalculator sqrtRatioCalculator;

  public ShallueVanDeWoestijneMapToCurve(final ECParameterSpec ecParameterSpec,
      final BigInteger z) {
    this.ecParameterSpec = ecParameterSpec;
    this.z = z;
    this.sqrtRatioCalculator = new GenericSqrtRatioCalculator(ecParameterSpec, z);
  }

  /**
   * Processes the given input value to map it to an elliptic curve point using the Shallue-van de
   * Woestijne algorithm, optimized for Weierstrass curves. This implementation adheres to the
   * specifications outlined in RFC 9380, section 6.6.2, and section F.2 for efficient computation.
   *
   * <p>The method computes the x and y coordinates for the point on the elliptic curve, using
   * modular arithmetic and auxiliary functions for square root computation and conditional
   * assignments.
   *
   * @param u the input value to be mapped to a point on the elliptic curve
   * @return the computed point on the elliptic curve represented as an ECPoint
   */
  @Override
  public ECPoint process(final BigInteger u) {

    final BigInteger A = this.ecParameterSpec.getCurve().getA().toBigInteger();
    final BigInteger B = this.ecParameterSpec.getCurve().getB().toBigInteger();
    final BigInteger p = this.ecParameterSpec.getCurve().getField().getCharacteristic();

    BigInteger tv1 = u.modPow(BigInteger.TWO, p);
    tv1 = this.z.multiply(tv1).mod(p);
    BigInteger tv2 = tv1.modPow(BigInteger.TWO, p);
    tv2 = tv2.add(tv1).mod(p);
    BigInteger tv3 = tv2.add(BigInteger.ONE).mod(p);
    tv3 = B.multiply(tv3).mod(p);
    BigInteger tv4 = H2cUtils.cmov(this.z, tv2.negate(), !tv2.equals(BigInteger.ZERO));
    tv4 = A.multiply(tv4).mod(p);
    tv2 = tv3.modPow(BigInteger.TWO, p);
    BigInteger tv6 = tv4.modPow(BigInteger.TWO, p);
    BigInteger tv5 = A.multiply(tv6).mod(p);
    tv2 = tv2.add(tv5).mod(p);
    tv2 = tv2.multiply(tv3).mod(p);
    tv6 = tv6.multiply(tv4).mod(p);
    tv5 = B.multiply(tv6).mod(p);
    tv2 = tv2.add(tv5).mod(p);
    BigInteger x = tv1.multiply(tv3).mod(p);
    final SqrtRatio sqrtRatio = this.sqrtRatioCalculator.sqrtRatio(tv2, tv6);
    final boolean isGx1Square = sqrtRatio.isQR();
    final BigInteger y1 = sqrtRatio.ratio();
    BigInteger y = tv1.multiply(u).mod(p);
    y = y.multiply(y1).mod(p);
    x = H2cUtils.cmov(x, tv3, isGx1Square);
    y = H2cUtils.cmov(y, y1, isGx1Square);
    final boolean e1 =
        H2cUtils.sgn0(u, this.ecParameterSpec) == H2cUtils.sgn0(y, this.ecParameterSpec);
    y = H2cUtils.cmov(y.negate(), y, e1).mod(p);
    x = x.multiply(tv4.modPow(BigInteger.ONE.negate(), p)).mod(p);
    return this.ecParameterSpec.getCurve().createPoint(x, y);
  }

}
