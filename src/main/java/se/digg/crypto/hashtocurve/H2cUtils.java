// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import java.math.BigInteger;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * Utility functions for hash 2 curve.
 */
@Slf4j
public class H2cUtils {

  /**
   * Constant time implementation of selection of value based on condition.
   *
   * @param a value selected on condition = false
   * @param b value selected on condition = true
   * @param condition condition
   * @param <T> the type of object to select
   * @return 'a' if condition is false, else 'b'
   */
  public static <T> T cmov(final T a, final T b, final boolean condition) {
    // This selection method in Java is constant time, independent on the value of 'condition'
    return condition ? b : a;
  }

  /**
   * Test if a value is square in a curve order.
   *
   * @param val value to test
   * @param order curve order
   * @return true if val is square
   */
  public static boolean isSquare(final BigInteger val, final BigInteger order) {
    final BigInteger modPow =
        val.modPow(order.subtract(BigInteger.ONE).divide(BigInteger.TWO), order);
    return modPow.equals(BigInteger.ONE) || modPow.equals(BigInteger.ZERO);
  }

  /**
   * Calculate the square root of val in a curve order.
   *
   * @param val value
   * @param order curve order
   * @return square root of val in curve order
   */
  public static BigInteger sqrt(final BigInteger val, final BigInteger order) {
    // Get the largest integer c1 where 2^c1 divides order - 1
    final int c1 = order.subtract(BigInteger.ONE).getLowestSetBit();
    final BigInteger c2 = order.subtract(BigInteger.ONE).divide(BigInteger.TWO.pow(c1));
    final BigInteger c3 = c2.subtract(BigInteger.ONE).divide(BigInteger.TWO);
    final BigInteger c4 = getFirstNonSquare(order);
    final BigInteger c5 = c4.modPow(c2, order);

    // Procedure
    BigInteger z = val.modPow(c3, order);
    BigInteger t = z.multiply(z).multiply(val).mod(order);
    z = z.multiply(val).mod(order);
    BigInteger b = t;
    BigInteger c = c5;
    for (int i = c1; i >= 2; i--) {
      for (int j = 1; j <= i - 2; j++) {
        b = b.multiply(b).mod(order);
      }
      final boolean e = b.equals(BigInteger.ONE);
      final BigInteger zt = z.multiply(c).mod(order);
      z = cmov(zt, z, e);
      c = c.multiply(c).mod(order);
      final BigInteger tt = t.multiply(c).mod(order);
      t = cmov(tt, t, e);
      b = t;
    }
    return z;
  }

  /**
   * Returns the sign of the BigInteger 'val' using the given ECParameterSpec 'spec'.
   *
   * @param val the BigInteger value
   * @param spec the ECParameterSpec specifying the curve field
   * @return the sign of 'val'
   * @throws IllegalArgumentException if spec.getCurve().getField().getDimension() != 1
   */
  public static int sgn0(final BigInteger val, final ECParameterSpec spec) {
    if (spec.getCurve().getField().getDimension() == 1) {
      return val.mod(BigInteger.TWO).intValue();
    }
    // TODO implement sign0 test for extension fields
    throw new IllegalArgumentException("Extension fields != 1 is not implemented yet");
  }

  /**
   * Calculates the modular inverse of a BigInteger 'val' with respect to a given BigInteger
   * 'order'.
   *
   * @param val the BigInteger value to calculate the inverse for
   * @param order the BigInteger representing the order
   * @return the modular inverse of 'val' with respect to 'order'
   */
  public static BigInteger inv0(final BigInteger val, final BigInteger order) {
    return val.modInverse(order);
  }

  /**
   * Convert an integer value to a byte array of a specified length.
   *
   * @param val the integer value to be converted
   * @param len the length of the resulting byte array
   * @return the byte array representation of the integer value
   * @throws IllegalArgumentException if the value requires more bytes than the assigned length size
   */
  public static byte[] i2osp(final int val, final int len) {
    final byte[] lengthVal = new BigInteger(String.valueOf(val)).toByteArray();
    byte[] paddedLengthVal = lengthVal.clone();
    if (paddedLengthVal.length > 1 && paddedLengthVal[0] == 0x00) {
      // Remove leading 00
      paddedLengthVal = Arrays.copyOfRange(paddedLengthVal, 1, paddedLengthVal.length);
    }
    if (paddedLengthVal.length > len) {
      throw new IllegalArgumentException("Value require more bytes than the assigned length size");
    }

    if (paddedLengthVal.length < len) {
      // Pad up to expected size
      for (int i = paddedLengthVal.length; i < len; i++) {
        paddedLengthVal = Arrays.concatenate(new byte[] {0x00}, paddedLengthVal);
      }
    }
    return paddedLengthVal;
  }

  /**
   * Converts a byte array to a BigInteger.
   *
   * @param val the byte array to convert
   * @return the BigInteger representation of the byte array
   */
  public static BigInteger os2ip(final byte[] val) {
    // Make sure we get a positive value by adding 0x00 as leading byte in the value byte array
    return new BigInteger(Arrays.concatenate(new byte[] {0x00}, val));
  }

  /**
   * Performs bitwise XOR operation on two byte arrays.
   *
   * @param arg1 the first byte array
   * @param arg2 the second byte array
   * @return the result of the XOR operation as a new byte array
   * @throws NullPointerException if either arg1 or arg2 is null
   * @throws IllegalArgumentException if arg1 and arg2 have different lengths
   */
  public static byte[] xor(final byte[] arg1, final byte[] arg2) {
    Objects.requireNonNull(arg1, "XOR argument must not be null");
    Objects.requireNonNull(arg2, "XOR argument must not be null");

    if (arg1.length != arg2.length) {
      throw new IllegalArgumentException("XOR operation on parameters of different lengths");
    }
    final byte[] xorArray = new byte[arg1.length];
    for (int i = 0; i < arg1.length; i++) {
      xorArray[i] = (byte) (arg1[i] ^ arg2[i]);
    }
    return xorArray;
  }

  /**
   * Get the first non-square member of the curve order.
   *
   * @param order curve order
   * @return first non-square member of the curve order
   */
  @SuppressWarnings("PMD.AvoidThrowingRawExceptionTypes")
  @edu.umd.cs.findbugs.annotations.SuppressFBWarnings(
      value = "THROWS_METHOD_THROWS_RUNTIMEEXCEPTION",
      justification = "RuntimeException is appropriate for illegal field state")
  private static BigInteger getFirstNonSquare(final BigInteger order) {
    final BigInteger maxCount = new BigInteger("1000");
    BigInteger nonSquare = BigInteger.ONE;
    while (isSquare(nonSquare, order)) {
      nonSquare = nonSquare.add(BigInteger.ONE);
      if (nonSquare.compareTo(maxCount) > 0) {
        throw new RuntimeException("Illegal Field. No non square value can be found");
      }
    }
    return nonSquare;
  }

}
