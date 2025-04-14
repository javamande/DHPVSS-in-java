package org.example.pvss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.junit.Test;

public class Dist_DummyAggregation {
    @Test
    public void testAggregateUV_SimpleCase1() {
        // Use a small prime modulus for the dummy group.
        BigInteger modulus = new BigInteger("7919"); // small prime for test
        DummyECPoint G = DummyECPoint.getGenerator(modulus);

        int n = 3; // number of participants
        // Fixed evaluation points (dummy values) and dual‑code coefficients for
        // controlled testing.
        // Note: evaluations[0] is unused (or serves as the designated point).
        BigInteger[] evaluations = { BigInteger.ZERO, BigInteger.ONE,
                BigInteger.valueOf(2), BigInteger.valueOf(3) };
        BigInteger[] dualCoeffs = { new BigInteger("2"), new BigInteger("3"), new BigInteger("4") };

        // Set a fixed dealer secret.
        BigInteger dealerSecret = new BigInteger("7");

        // Create dummy ephemeral keys.
        DummyECPoint[] ephemeralKeys = new DummyECPoint[n];
        for (int i = 0; i < n; i++) {
            // For simplicity, let ephemeralKey[i] = (i+2)*G.
            ephemeralKeys[i] = G.multiply(BigInteger.valueOf(i + 2));
        }

        // Create dummy encrypted shares so that each one is calculated as:
        // encryptedShare[i] = dealerSecret * ephemeralKey[i].
        // (This mimics the encryption step: C_i = A_i + (sk_D * E_i), if we set A_i =
        // identity.)
        DummyECPoint[] encryptedShares = new DummyECPoint[n];
        for (int i = 0; i < n; i++) {
            encryptedShares[i] = ephemeralKeys[i].multiply(dealerSecret);
        }

        // Now aggregate U and V from the dummy data.
        // Here, for each participant, we weight their ephemeralKey andencryptedShare
        // by
        // a scalar: evaluations[i] * dualCoeffs[i-1] mod modulus.
        DummyECPoint U = DummyECPoint.infinity(modulus);
        DummyECPoint V = DummyECPoint.infinity(modulus);
        for (int i = 1; i <= n; i++) {
            BigInteger scalar = evaluations[i].multiply(dualCoeffs[i - 1]).mod(modulus);
            DummyECPoint termU = ephemeralKeys[i - 1].multiply(scalar);
            DummyECPoint termV = encryptedShares[i - 1].multiply(scalar);
            System.out.println("For participant " + i + ": termU = " + termU + ", termV = " + termV);
            U = U.add(termU);
            V = V.add(termV);
        }

        // Expected V should equal [dealerSecret] * U.
        DummyECPoint expectedV = U.multiply(dealerSecret);

        System.out.println("Aggregated U = " + U);
        System.out.println("Aggregated V = " + V);
        System.out.println("Expected V = " + expectedV);

        assertNotNull("Aggregated U should not be null", U);
        assertNotNull("Aggregated V should not be null", V);
        assertEquals("V should equal dealerSecret * U", expectedV, V);
    }

    @Test
    public void testAggregateUVWithDummyShares() {
        // Use a small prime modulus for testing with dummy points.
        BigInteger modulus = new BigInteger("7919"); // small prime for testing

        // Here we use a dummy implementation of ECPoint (or use your DummyECPoint) that
        // supports the required operations.
        DummyECPoint G = DummyECPoint.getGenerator(modulus);

        // Let's simulate a scenario with n = 3 participants.
        int n = 3;

        // Fixed evaluation points are irrelevant in this dummy test, but we define them
        // for
        // completeness.
        BigInteger[] evaluations = new BigInteger[] {
                BigInteger.ZERO, // index 0 (unused)
                BigInteger.ONE,
                BigInteger.valueOf(2),
                BigInteger.valueOf(3)
        };

        // Choose fixed dual‑code coefficients (for testing, use small numbers).
        BigInteger[] dualCoeffs = new BigInteger[] {
                new BigInteger("2"),
                new BigInteger("3"),
                new BigInteger("4")
        };

        // Generate dummy ephemeral keys and "encrypted shares".
        // In this dummy test, we force the Shamir share Aᵢ to be the identity element.
        DummyECPoint[] ephemeralKeys = new DummyECPoint[n];
        DummyECPoint[] encryptedShares = new DummyECPoint[n];
        DummyECPoint identity = DummyECPoint.infinity(modulus); // The additive identity in EC.
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < n; i++) {
            // For testing, generate ephemeral keys as simple multiples of G.
            ephemeralKeys[i] = G.multiply(BigInteger.valueOf(i + 2));
            // Set the Shamir share Aᵢ to be identity, so that the encrypted share is
            // simply:
            // Cᵢ = identity + (sk_D * ephemeralKey_i) = sk_D * ephemeralKey_i.
            // For the dummy test, we simulate this by computing:
            encryptedShares[i] = ephemeralKeys[i].multiply(BigInteger.ZERO); // start with 0...
        }
        // Now choose a fixed dealer secret.
        BigInteger dealerSecret = new BigInteger("7");

        // Now compute the encrypted shares with masking.
        // Since we want Aᵢ = identity, we compute:
        // Cᵢ = Aᵢ + (sk_D * Eᵢ) = identity + (sk_D * Eᵢ) = sk_D * Eᵢ.
        for (int i = 0; i < n; i++) {
            // Compute the mask: Mᵢ = [sk_D] * ephemeralKeys[i]
            DummyECPoint mask = ephemeralKeys[i].multiply(dealerSecret);
            // Encrypted share = Aᵢ (identity) + mask = mask.
            encryptedShares[i] = identity.add(mask);
        }

        // Aggregate U as the sum of all ephemeral keys.
        DummyECPoint U = DummyECPoint.infinity(modulus);
        // Aggregate V as the sum of all encrypted shares.
        DummyECPoint V = DummyECPoint.infinity(modulus);
        for (int i = 0; i < n; i++) {
            U = U.add(ephemeralKeys[i]);
            V = V.add(encryptedShares[i]);
        }

        // The expected V is computed as:
        // expectedV = [dealerSecret] * U.
        DummyECPoint expectedV = U.multiply(dealerSecret);

        System.out.println("Dummy Test AggregateUV:");
        System.out.println("Ephemeral keys (Eᵢ):");
        for (int i = 0; i < n; i++) {
            System.out.println("  E_" + (i + 1) + " = " + ephemeralKeys[i]);
        }
        System.out.println("Encrypted shares (Cᵢ):");
        for (int i = 0; i < n; i++) {
            System.out.println("  C_" + (i + 1) + " = " + encryptedShares[i]);
        }
        System.out.println("Aggregated U (∑Eᵢ) = " + U);
        System.out.println("Aggregated V (∑Cᵢ) = " + V);
        System.out.println("Expected V = dealerSecret * U = " + expectedV);

        // Now assert that the aggregated V equals expectedV.
        assertNotNull("Aggregated U must not be null", U);
        assertNotNull("Aggregated V must not be null", V);
        assertEquals("V should equal dealerSecret * U", expectedV, V);
    }
}
