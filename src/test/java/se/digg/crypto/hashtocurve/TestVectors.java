// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import se.digg.crypto.hashtocurve.data.HashToCurveProfile;

/**
 * Functions to obtain test vector data
 */
public class TestVectors {

  public static final ObjectMapper OBJECT_MAPPER;

  static {
    OBJECT_MAPPER = new ObjectMapper();
    OBJECT_MAPPER.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  public static TestVectorData getTestVectors(HashToCurveProfile profile) {
    try {
      return OBJECT_MAPPER.readValue(
          TestVectors.class.getResourceAsStream("/" + profile.getCipherSuiteID() + ".json"),
          TestVectorData.class);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

}
