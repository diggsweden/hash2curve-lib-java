// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.impl;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.Test;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

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