// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.impl;

import java.math.BigInteger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.Test;

/**
 * Test class for the GenericSqrtRatioCalculator
 */
public class GenericSqrtRatioCalculatorTest {

  @Test
  public void testCalculateC1_IsCorrect() {
    ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
    BigInteger z = BigInteger.valueOf(-10);
    GenericSqrtRatioCalculator calc = new GenericSqrtRatioCalculator(ecParameterSpec, z);
    calc.sqrtRatio(BigInteger.ONE, BigInteger.TWO);
  }
}
