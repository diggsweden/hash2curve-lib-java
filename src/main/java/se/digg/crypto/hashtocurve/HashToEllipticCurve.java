// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import java.math.BigInteger;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.math.ec.ECPoint;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;

/**
 * Main class for implementing hash to elliptic curve according to RFC 9380.
 *
 * <p><code>
 * Steps:
 * 1. u = hash_to_field(msg, 2)
 * 2. Q0 = map_to_curve(u[0])
 * 3. Q1 = map_to_curve(u[1])
 * 4. R = Q0 + Q1 # Point addition
 * 5. P = clear_cofactor(R)
 * 6. return P
 * </code>
 */
@RequiredArgsConstructor
public class HashToEllipticCurve {

  protected final HashToField hashToField;
  protected final MapToCurve mapToCurve;
  protected final CurveProcessor curveProcessor;

  public static HashToEllipticCurve getInstance(final HashToCurveProfile profile) {
    return null;
  }

  /**
   * Hashes a message to an elliptic curve point.
   *
   * @param message the message to be hashed
   * @return the resulting elliptic curve point P
   */
  public ECPoint hashToEllipticCurve(final byte[] message) {
    final BigInteger[][] u = this.hashToField.process(message);
    final ECPoint Q0 = this.mapToCurve.process(u[0][0]);
    final ECPoint Q1 = this.mapToCurve.process(u[1][0]);
    final ECPoint R = Q0.add(Q1);
    return this.curveProcessor.clearCofactor(R);
  }

}
