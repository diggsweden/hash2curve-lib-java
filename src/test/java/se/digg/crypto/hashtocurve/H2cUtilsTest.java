// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.Security;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.digg.crypto.hashtocurve.impl.GenericOPRFHashToScalar;

/**
 * Testing hash 2 curve utility functions
 */
@Slf4j
class H2cUtilsTest {

  static ECParameterSpec p256Spec = ECNamedCurveTable.getParameterSpec("P-256");
  static GenericOPRFHashToScalar hashToScalar =
      new GenericOPRFHashToScalar(p256Spec, new SHA256Digest(), 48);

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  void isSquareTest() throws Exception {

    boolean[] expectedValues =
        new boolean[] {true, false, false, true, true, false, false, false, true, false};

    log.info("P256 curve order: {}", p256Spec.getCurve().getOrder().toString(16));

    for (int i = 0; i < 10; i++) {
      BigInteger x = hashToScalar.process(String.valueOf(i).getBytes(), "DST".getBytes());
      boolean square = H2cUtils.isSquare(x, p256Spec.getCurve().getOrder());
      log.info("Integer {} square in p256 order: {}", x.toString(16), square);
      assertEquals(expectedValues[i], square);
    }
  }

  @Test
  void sqrtTest() throws Exception {

    String[] expectedValues = {
        "323f7ed2e7c1bd98c010e4f7682e424fd7434feeca6a39ad7f80f3dea00eb18d",
        "1e5f775dc6b369930f58df140498358437461c96cb2857c489c346e3927b6a83",
        "56af41b8f8b6f29f556d1d4471f763a7429d5032fde2156d93d50273858453da",
        "2e1d7226dfcd493860543685107d79a684c11c635cec44b0ed1db566cb3c48d2",
        "92bbc6e0dc62c4f3488cb336c911c75108bddbcd60ad7a2ad7f62f07ecf5ddd8",
        "3f32018e0754b2e744ecd06c9b77e7de171f07e6ad6daf6e914e94108db91073",
        "82353b2f3c9505d15429d6a4d5dd4231c3d116e7300efb39f1deca18164bddf6",
        "3afc13643cc49fb989bd18bde7c2ac2332a99381f3f6081293346e1595fca93d",
        "e4244d900f35a71f23ed02dff6c2bc22f11ca4ebb8dd51e0fcaefd0bd7caeed4",
        "b3ed944452119b21901b25b211c0a5d2f9b40384269c77f488064c9503296bd0"
    };

    for (int i = 0; i < 10; i++) {
      BigInteger x = hashToScalar.process(String.valueOf(i).getBytes(), "DST".getBytes());
      BigInteger sqrt = H2cUtils.sqrt(x, p256Spec.getCurve().getOrder());
      log.info("Integer {} sqrt in p256 order: {}", x.toString(16), sqrt.toString(16));
      assertEquals(expectedValues[i], sqrt.toString(16));
    }

  }

}
