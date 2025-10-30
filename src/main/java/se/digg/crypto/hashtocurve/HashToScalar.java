// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import java.math.BigInteger;

/**
 * Interface for the Hash to Scalar operation
 */
public interface HashToScalar {

  /**
   * Hash the given input bytes and domain separatin tag bytes as part of a Hash to Scalar
   * operation, producing a valid scalar on an eliptic curve.
   *
   * @param input the input byte array to be processed
   * @param dst the destination byte array used in the operation
   * @return the resulting BigInteger after hashing the input to a scalar on an eliptic curve
   */
  BigInteger process(byte[] input, byte[] dst);

}
