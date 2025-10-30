// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.impl;

import java.math.BigInteger;
import org.bouncycastle.jce.spec.ECParameterSpec;
import se.digg.crypto.hashtocurve.H2cUtils;
import se.digg.crypto.hashtocurve.SqrtRatioCalculator;
import se.digg.crypto.hashtocurve.data.SqrtRatio;

/**
 * Generic implementation of the SqrtRatio calculator.
 */
public class GenericSqrtRatioCalculator implements SqrtRatioCalculator {

  private final BigInteger q;

  private final int c1;
  private final BigInteger c2, c3, c4, c5, c6, c7;

  public GenericSqrtRatioCalculator(final ECParameterSpec ecParameterSpec, final BigInteger z) {
    this.q = ecParameterSpec.getCurve().getField().getCharacteristic();
    this.c1 = this.calculateC1();

    this.c2 = this.q.subtract(BigInteger.ONE).divide(BigInteger.TWO.pow(this.c1));
    this.c3 = this.c2.subtract(BigInteger.ONE).divide(BigInteger.TWO);
    this.c4 = BigInteger.TWO.pow(this.c1).subtract(BigInteger.ONE);
    this.c5 = BigInteger.TWO.pow(this.c1 - 1);
    this.c6 = z.modPow(this.c2, this.q);
    this.c7 = z.modPow(this.c2.add(BigInteger.ONE).divide(BigInteger.TWO), q);
  }

  private int calculateC1() {
    BigInteger qMinusOne = this.q.subtract(BigInteger.ONE);
    int c1 = 0;
    while (qMinusOne.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
      qMinusOne = qMinusOne.divide(BigInteger.TWO);
      c1++;
    }
    return c1;
  }

  @Override
  public SqrtRatio sqrtRatio(final BigInteger u, final BigInteger v) {

    BigInteger tv1 = this.c6;
    BigInteger tv2 = v.modPow(this.c4, this.q);
    BigInteger tv3 = tv2.modPow(BigInteger.TWO, this.q);
    tv3 = tv3.multiply(v).mod(this.q);
    BigInteger tv5 = u.multiply(tv3).mod(this.q);
    tv5 = tv5.modPow(this.c3, this.q);
    tv5 = tv5.multiply(tv2).mod(this.q);
    tv2 = tv5.multiply(v).mod(this.q);
    tv3 = tv5.multiply(u).mod(this.q);
    BigInteger tv4 = tv3.multiply(tv2).mod(this.q);
    tv5 = tv4.modPow(this.c5, this.q);
    final boolean isQR = tv5.equals(BigInteger.ONE);
    tv2 = tv3.multiply(this.c7).mod(this.q);
    tv5 = tv4.multiply(tv1).mod(this.q);
    tv3 = H2cUtils.cmov(tv2, tv3, isQR);
    tv4 = H2cUtils.cmov(tv5, tv4, isQR);
    for (int i = this.c1; i >= 2; i--) {
      tv5 = BigInteger.valueOf(i - 2);
      tv5 = BigInteger.TWO.pow(tv5.intValue());
      tv5 = tv4.modPow(tv5, this.q);
      final boolean e1 = tv5.equals(BigInteger.ONE);
      tv2 = tv3.multiply(tv1).mod(this.q);
      tv1 = tv1.multiply(tv1).mod(this.q);
      tv5 = tv4.multiply(tv1).mod(this.q);
      tv3 = H2cUtils.cmov(tv2, tv3, e1);
      tv4 = H2cUtils.cmov(tv5, tv4, e1);
    }
    return new SqrtRatio(isQR, tv3);
  }
}
