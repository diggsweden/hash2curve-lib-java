package se.digg.crypto.hashtocurve.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.hashtocurve.MessageExpansion;

import java.math.BigInteger;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test HashToScalar
 */
@Slf4j
class GenericOPRFHashToScalarTest {

  static ECParameterSpec p256Spec = ECNamedCurveTable.getParameterSpec("P-256");
  static GenericOPRFHashToScalar hashToScalar = new GenericOPRFHashToScalar(p256Spec, new SHA256Digest(), 128);

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }


  @Test
  public void testHashToScalar() {

    BigInteger scalar = hashToScalar.process("Hej".getBytes(), "DST".getBytes());
    log.info("Scalar value: {}", scalar.toString(16));

  }


  @Test
  public void testMessageExpansion() {

    MessageExpansion messageExpansion = new XmdMessageExpansion(new SHA256Digest(), 48);
    byte[] expandMessage = messageExpansion.expandMessage("Hej".getBytes(), "DST".getBytes(), 48);

    log.info("Expanded message: {}", Hex.toHexString(expandMessage));



  }



}