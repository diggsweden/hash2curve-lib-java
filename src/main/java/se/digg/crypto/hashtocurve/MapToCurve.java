// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Interface for Map to Curve.
 */
public interface MapToCurve {

  /**
   * Processes the given BigInteger element and maps it to a point on the elliptic curve, as defined
   * by the hash 2 curve specification.
   *
   * @param element the input BigInteger element to be mapped to a point on the curve
   * @return the elliptic curve point corresponding to the input element
   */
  ECPoint process(BigInteger element);

}
