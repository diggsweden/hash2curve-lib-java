// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.impl;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.digg.crypto.hashtocurve.MessageExpansion;

@Slf4j
public class GenericHashToFieldTest {

  private static ECParameterSpec ecParameterSpec;
  private static MessageExpansion messageExpansion;

  @BeforeAll
  public static void setup() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    ecParameterSpec = ECNamedCurveTable.getParameterSpec("P-256");
    messageExpansion = new XmdMessageExpansion(new SHA256Digest(), 128);
  }

  @Test
  public void testGenericHashToField() {
    byte[] message = new byte[] {};
    byte[] dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.UTF_8);
    GenericHashToField testInstance = new GenericHashToField(dst, ecParameterSpec, messageExpansion, 48);
    BigInteger[][] result = testInstance.process(message);

    log.info("U0 : {}", Hex.toHexString(result[0][0].toByteArray()));
    log.info("U1 : {}", Hex.toHexString(result[1][0].toByteArray()));

  }
}