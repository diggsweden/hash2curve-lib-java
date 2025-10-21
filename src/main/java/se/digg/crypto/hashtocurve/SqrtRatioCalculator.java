// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import java.math.BigInteger;

import se.digg.crypto.hashtocurve.data.SqrtRatio;

/**
 * Interface for a calculator of SqrtRatio
 */
public interface SqrtRatioCalculator {

  /**
   * he sqrtRatio subroutine of hash2Curve in the field F
   *
   * @param u u parameter, element of F
   * @param v v parameter, element of F, such that v != 0
   * @return SqrtRatio result
   */
  SqrtRatio sqrtRatio(BigInteger u, BigInteger v);

}
