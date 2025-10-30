// SPDX-FileCopyrightText: 2025 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.data;

import java.math.BigInteger;

/**
 * The result of a sqrt_ration calculation.
 */
public record SqrtRatio(
        boolean isQR,
        BigInteger ratio) {
}
