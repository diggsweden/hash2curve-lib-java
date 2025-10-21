// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.impl;

import java.math.BigInteger;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jce.spec.ECParameterSpec;

import se.digg.crypto.hashtocurve.HashToScalar;
import se.digg.crypto.hashtocurve.MessageExpansion;

/**
 * Generic implementation of Hash to Scalar for OPRF
 */
public class GenericOPRFHashToScalar implements HashToScalar {

  private final ECParameterSpec ecParameterSpec;
  private final MessageExpansion messageExpansion;

  private final int L;

  public GenericOPRFHashToScalar(final ECParameterSpec ecParameterSpec, final Digest digest, final int k) {
    this.ecParameterSpec = ecParameterSpec;
    this.L =
        (int) Math.ceil(((double) ecParameterSpec.getCurve().getOrder().subtract(BigInteger.ONE).bitLength() + k) / 8);
    this.messageExpansion = new XmdMessageExpansion(digest, k);
  }

  @Override
  public BigInteger process(final byte[] input, final byte[] dst) {
    final byte[] expandMessage = this.messageExpansion.expandMessage(input, dst, this.L);
    return new BigInteger(1, expandMessage).mod(this.ecParameterSpec.getCurve().getOrder());
  }
}
