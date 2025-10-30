// SPDX-FileCopyrightText: 2025 The Hash To Curve Authors
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.crypto.hashtocurve.data;

import org.bouncycastle.math.ec.ECPoint;

/**
 * The Hash to field points produced by hash_to_field(msg, 2)
 */
public record MapToCurvePoints(
    ECPoint q0,
    ECPoint q1) {

}
