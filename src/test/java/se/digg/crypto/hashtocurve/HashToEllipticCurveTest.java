// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.List;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;
import se.digg.crypto.hashtocurve.impl.GenericCurveProcessor;
import se.digg.crypto.hashtocurve.impl.GenericHashToField;
import se.digg.crypto.hashtocurve.impl.ShallueVanDeWoestijneMapToCurve;
import se.digg.crypto.hashtocurve.impl.XmdMessageExpansion;

/**
 * Test suite for HashToEllipticCurve class.
 */
@Slf4j
public class HashToEllipticCurveTest {

  @BeforeAll
  public static void setup() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void testTestVectors() throws Exception {

    //TODO Add support for Montgomery curves (required for curve25519).

    List<HashToCurveProfile> profileList = List.of(
        HashToCurveProfile.P256_XMD_SHA_256_SSWU_RO_,
        HashToCurveProfile.P384_XMD_SHA_384_SSWU_RO_,
        HashToCurveProfile.P521_XMD_SHA_512_SSWU_RO_
        //    HashToCurveProfile.curve25519_XMD_SHA_512_ELL2_RO_
    );

    for (HashToCurveProfile profile : profileList) {
      performTestOnSpecificCurveProfile(profile, false);
    }
  }

  public void performTestOnSpecificCurveProfile(HashToCurveProfile profile, boolean useTestVectorU)
      throws Exception {
    TestVectorData tvd = TestVectors.getTestVectors(profile);
    BigInteger Z = h2bi(tvd.getZ(), tvd.getField().getP());
    int L = h2bi(tvd.getL()).intValue();
    log.info("Performing test vector tests on ciphersuite: {}", profile.getCipherSuiteID());
    log.info("Details:\n"
            + "   Curve: {}\n"
            + "   Hash: {}\n"
            + "   dst: {}\n"
            + "   L: {}\n"
            + "   Z: {}\n"
            + "   Field m: {}\n"
            + "   Field p: {}\n"
        , tvd.getCurve(), tvd.getHash(), tvd.getDst(), L, Z,
        tvd.getField().getM(), tvd.getField().getP());

    ECParameterSpec spec = switch (profile) {
      case P256_XMD_SHA_256_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-256");
      case P384_XMD_SHA_384_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-384");
      case P521_XMD_SHA_512_SSWU_RO_ -> ECNamedCurveTable.getParameterSpec("P-521");
      case curve25519_XMD_SHA_512_ELL2_RO_ -> ECNamedCurveTable.getParameterSpec("curve25519");
    };
    Digest digest = switch (profile) {
      case P256_XMD_SHA_256_SSWU_RO_ -> new SHA256Digest();
      case P384_XMD_SHA_384_SSWU_RO_ -> new SHA384Digest();
      case P521_XMD_SHA_512_SSWU_RO_ -> new SHA512Digest();
      case curve25519_XMD_SHA_512_ELL2_RO_ -> new SHA512Digest();
    };

    CurveProcessor curveProcessor = new GenericCurveProcessor(spec);
    MessageExpansion messExp = new XmdMessageExpansion(digest, profile.getK());
    GenericHashToField hashToField =
        new GenericHashToField(tvd.getDst().getBytes(StandardCharsets.UTF_8), spec, messExp,
            profile.getL());
    MapToCurve mapToCurve = new ShallueVanDeWoestijneMapToCurve(spec, profile.getZ());

    assertEquals(Z, profile.getZ());
    assertEquals(L, profile.getL());

    TestHashToEllipticCurve h2c =
        new TestHashToEllipticCurve(hashToField, mapToCurve, curveProcessor);

    // Run individual vectors
    List<TestVectorData.Vector> vectors = tvd.getVectors();
    for (TestVectorData.Vector vector : vectors) {

      if (useTestVectorU) {
        // Replace with test vector u values
        h2c.setNextU0(h2bi(vector.getU().get(0)));
        h2c.setNextU1(h2bi(vector.getU().get(1)));
      }

      ECPoint point =
          executeAndLogResult("Results for msg: " + vector.getMsg(), vector.getMsg(), h2c,
              hexStrip(vector.getP().get("x")), hexStrip(vector.getP().get("y")));
      compare(vector.getP().get("x"), vector.getP().get("y"), point);
    }

  }

  private void compare(String x, String y, ECPoint point) {
    log.info("Expected X: {}", hexStrip(x));
    log.info("Expected Y: {}", hexStrip(y));
    log.info("Expected compressed point: {}", Hex.toHexString(point.getEncoded(true)));
    String resultX = point.getXCoord().toBigInteger().toString(16);
    String resultY = point.getYCoord().toBigInteger().toString(16);
    hexCompare(hexStrip(x), resultX);
    hexCompare(hexStrip(y), resultY);
    log.info("Points match\n");
  }

  private void hexCompare(String vectorVal, String resultVal) {
    int startIndex = vectorVal.length() - resultVal.length();
    assertEquals(vectorVal.substring(startIndex), resultVal);
  }

  public ECPoint executeAndLogResult(String description, String msg, HashToEllipticCurve h2c,
      String px, String py) throws Exception {
    log.info(description);
    ECPoint ecPoint = h2c.hashToEllipticCurve(msg.getBytes(StandardCharsets.UTF_8));
    String x = ecPoint.getXCoord().toString();
    log.info("Result point X: {}", x);
    String y = ecPoint.getYCoord().toString();
    log.info("Result point Y: {}", y);
    return ecPoint;
  }

  BigInteger h2bi(String hexStr) {
    return new BigInteger(hexStrip(hexStr), 16);
  }

  BigInteger h2bi(String hexStr, String hexOrder) {
    BigInteger val = h2bi(hexStr);
    BigInteger order = h2bi("00" + hexStrip(hexOrder));

    BigInteger positive = val;
    BigInteger negative = order.subtract(val);
    BigInteger result = positive.compareTo(negative) > 0 ? negative.negate() : positive;
    return result;
  }

  private String hexStrip(String hexStr) {
    return hexStr.startsWith("0x") || hexStr.startsWith("0X")
        ? hexStr.substring(2)
        : hexStr;
  }

  public static class TestHashToEllipticCurve extends HashToEllipticCurve {

    public TestHashToEllipticCurve(HashToField hashToField, MapToCurve mapToCurve,
        CurveProcessor curveProcessor) {
      super(hashToField, mapToCurve, curveProcessor);
    }

    @Setter
    BigInteger nextU0;
    @Setter
    BigInteger nextU1;

    @Override
    public ECPoint hashToEllipticCurve(byte[] message) {
      BigInteger[][] u = hashToField.process(message);
      ECPoint Q0 = mapToCurve.process(getU0(u));
      ECPoint Q1 = mapToCurve.process(getU1(u));
      ECPoint R = Q0.add(Q1);
      ECPoint P = curveProcessor.clearCofactor(R);
      return P;
    }

    BigInteger getU0(BigInteger[][] u) {
      log.info("Calculated u0: {}", u[0][0].toString(16));
      if (nextU0 != null) {
        log.info("Using preset u0: {}", nextU0.toString(16));
        BigInteger result = new BigInteger(nextU0.toString());
        nextU0 = null;
        return result;
      }
      return u[0][0];
    }

    BigInteger getU1(BigInteger[][] u) {
      log.info("Calculated u1: {}", u[1][0].toString(16));
      if (nextU1 != null) {
        log.info("Using preset u1: {}", nextU1.toString(16));
        BigInteger result = new BigInteger(nextU1.toString());
        nextU1 = null;
        return result;
      }
      return u[1][0];
    }

  }

}
