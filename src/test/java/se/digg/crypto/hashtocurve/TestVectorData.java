// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.List;

/**
 * Test vector data
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TestVectorData {

  @JsonProperty("L")
  private String L;

  @JsonProperty("Z")
  private String Z;

  @JsonProperty("ciphersuite")
  private String ciphersuite;

  @JsonProperty("curve")
  private String curve;

  @JsonProperty("dst")
  private String dst;

  @JsonProperty("expand")
  private String expand;

  @JsonProperty("field")
  private Field field;

  @JsonProperty("hash")
  private String hash;

  @JsonProperty("k")
  private String k;

  @JsonProperty("map")
  private Map<String, String> map;

  @JsonProperty("randomOracle")
  private boolean randomOracle;

  @JsonProperty("vectors")
  private List<Vector> vectors;

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class Field {

    @JsonProperty("m")
    private String m;

    @JsonProperty("p")
    private String p;
  }

  @Data
  @AllArgsConstructor
  @NoArgsConstructor
  public static class Vector {

    @JsonProperty("P")
    private Map<String, String> P;

    @JsonProperty("Q0")
    private Map<String, String> Q0;

    @JsonProperty("Q1")
    private Map<String, String> Q1;

    @JsonProperty("msg")
    private String msg;

    @JsonProperty("u")
    private List<String> u;
  }
}
