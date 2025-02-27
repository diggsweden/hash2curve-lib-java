package se.digg.crypto.hashtocurve.impl;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Arrays;
import se.digg.crypto.hashtocurve.H2cUtils;
import se.digg.crypto.hashtocurve.HashToField;
import se.digg.crypto.hashtocurve.MessageExpansion;

import java.math.BigInteger;

/**
 * Generic implementation of hash to field
 */
public class GenericHashToField implements HashToField {

  protected final byte[] dst;
  protected final ECParameterSpec ecParameterSpec;
  protected final MessageExpansion messageExpansion;
  /** Security parameter for the suite */
  protected int L;
  protected int m;
  protected BigInteger p;
  protected final int count;

  public GenericHashToField(final byte[] dst, final ECParameterSpec ecParameterSpec,
      final MessageExpansion messageExpansion, final int L) {
    this(dst, ecParameterSpec, messageExpansion, L, 2);
  }

  public GenericHashToField(final byte[] dst, final ECParameterSpec ecParameterSpec, final MessageExpansion messageExpansion, final int L,
      final int count) {
    this.dst = dst;
    this.ecParameterSpec = ecParameterSpec;
    this.count = count;
    this.L = L;
    this.messageExpansion = messageExpansion;
    this.p = ecParameterSpec.getCurve().getField().getCharacteristic();
    this.m = ecParameterSpec.getCurve().getField().getDimension();
  }

  @Override
  public BigInteger[][] process(final byte[] message) {

    final int byteLen = this.count * this.m * this.L;
    final byte[] uniformBytes = this.messageExpansion.expandMessage(message, this.dst, byteLen);
    final BigInteger[][] u = new BigInteger[this.count][this.m];
    for (int i = 0; i < this.count; i++) {
      final BigInteger[] e = new BigInteger[this.m];
      for (int j = 0; j < this.m; j++) {
        final int elmOffset = this.L * (j + i * this.m);
        final byte[] tv = Arrays.copyOfRange(uniformBytes, elmOffset, elmOffset + this.L);
        e[j] = H2cUtils.os2ip(tv).mod(this.p);
      }
      u[i] = e;
    }
    return u;
  }
}
