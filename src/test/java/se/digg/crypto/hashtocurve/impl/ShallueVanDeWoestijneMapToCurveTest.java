// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.impl;

import java.math.BigInteger;
import java.security.Security;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.hashtocurve.MapToCurve;

@Slf4j
public class ShallueVanDeWoestijneMapToCurveTest {



  /*
   * This test class is testing the "process" method in "ShallueVanDeWoestijneMapToCurve" class
   * which implements the Shallue van de Woestijne Map to curve according to section 6.6.1 of RFC
   * 9380.
   */
  @BeforeAll
  public static void setup() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  void processTest_WithGivenElement_ShouldWorkAsExpected() throws Exception {
    // Given
    ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");


    ShallueVanDeWoestijneMapToCurve mapToCurve =
        new ShallueVanDeWoestijneMapToCurve(ecParameterSpec, BigInteger.valueOf(-10));

    testSpecificMapping(new BigInteger(1,
        Hex.decode("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009")),
        mapToCurve);
    testSpecificMapping(new BigInteger(1,
        Hex.decode("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a")),
        mapToCurve);

    // u0 = new
    // BigInteger("78397231975818298121002851560982570386422970797899025056634496834376049971209");

  }

  void testSpecificMapping(BigInteger u, MapToCurve mapToCurve) throws Exception {
    log.info("Testing to map {}", u.toString(16));
    ECPoint qu = mapToCurve.process(u);
    log.info("Mapped point X: {}", qu.getXCoord().toBigInteger().toString(16));
    log.info("Mapped point Y: {}", qu.getYCoord().toBigInteger().toString(16));
  }

}
