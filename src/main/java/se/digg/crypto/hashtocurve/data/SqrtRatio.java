// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.data;

import java.math.BigInteger;

/**
 * The result of a sqrt_ration calculation
 */
public record SqrtRatio(
    boolean isQR,
    BigInteger ratio) {
}
