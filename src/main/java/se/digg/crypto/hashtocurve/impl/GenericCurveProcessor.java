package se.digg.crypto.hashtocurve.impl;

import java.math.BigInteger;
import java.security.spec.ECField;
import java.util.function.Predicate;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECAlgorithms;

import lombok.RequiredArgsConstructor;
import org.bouncycastle.math.field.FiniteField;
import se.digg.crypto.hashtocurve.CurveProcessor;
import se.digg.crypto.hashtocurve.H2cUtils;

@RequiredArgsConstructor
public class GenericCurveProcessor implements CurveProcessor {
  private final ECParameterSpec ecParameterSpec;

  @Override
  public ECPoint clearCofactor(final ECPoint ecPoint) {
    return ecPoint.multiply(this.ecParameterSpec.getH());
  }

}
