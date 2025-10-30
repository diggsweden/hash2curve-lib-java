// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Process curve specific functions.
 */
public interface CurveProcessor {

  /**
   * Clears the cofactor from the given elliptic curve point.
   *
   * @param ecPoint the elliptic curve point to process
   * @return the elliptic curve point with the cofactor cleared
   */
  ECPoint clearCofactor(ECPoint ecPoint);

}
