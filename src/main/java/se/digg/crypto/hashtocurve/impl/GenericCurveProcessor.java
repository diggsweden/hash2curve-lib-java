// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.impl;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import se.digg.crypto.hashtocurve.CurveProcessor;

@RequiredArgsConstructor
public class GenericCurveProcessor implements CurveProcessor {
  private final ECParameterSpec ecParameterSpec;

  @Override
  public ECPoint clearCofactor(final ECPoint ecPoint) {
    return ecPoint.multiply(this.ecParameterSpec.getH());
  }

}
