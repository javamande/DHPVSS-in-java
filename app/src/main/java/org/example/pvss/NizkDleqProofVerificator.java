package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

public class NizkDleqProofVerificator {
    /**
     * Verifies a DLEQ proof for the relation:
     *
     * Given that x = [α]G and y = [α]h, the proof demonstrates that the same scalar
     * α was used.
     *
     * Verification steps:
     * 1. Recompute a1' = [z]G + [e]x, and a2' = [z]h + [e]y.
     * 2. Compute H' = Hash(G, x, h, y, a1', a2') mod q.
     * 3. Use H' as the seed for a deterministic PRNG to obtain challenge e'.
     * 4. The proof verifies if e' equals the challenge in the proof.
     *
     * @param ctx   the PVSS context containing group parameters.
     * @param h     the second base (ECPoint).
     * @param x     the public value [α]G.
     * @param y     the public value [α]h.
     * @param proof the DLEQ proof containing the challenge e and response z.
     * @return true if the proof verifies; false otherwise.
     */
    public static boolean verifyProof(DhPvssContext ctx, ECPoint h, ECPoint x, ECPoint y, NizkDlEqProof proof) {
        BigInteger q = ctx.getGroupParameters().getN();
        ECPoint G = ctx.getGenerator();

        System.out.println("DLEQ Proof Verification:");
        System.out.println("  Received proof: e = " + proof.getChallenge() + ", z = " + proof.getResponse());

        // Step 1. Recompute commitments:
        // a1' = [z]G + [e]x and a2' = [z]h + [e]y.
        ECPoint a1Prime = G.multiply(proof.getResponse()).add(x.multiply(proof.getChallenge())).normalize();
        ECPoint a2Prime = h.multiply(proof.getResponse()).add(y.multiply(proof.getChallenge())).normalize();
        System.out.println("  Recomputed commitment a1': " + a1Prime);
        System.out.println("  Recomputed commitment a2': " + a2Prime);

        // Step 2. Compute the verification hash H' = Hash(G, x, h, y, a1', a2') mod q.
        BigInteger hashValue = Hash.hashElements(ctx, G, x, h, y, a1Prime, a2Prime).mod(q);
        System.out.println("  Verification hash value H' (mod q): " + hashValue);

        // Step 3. Seed a PRNG with H' and generate the challenge e'.
        SecureRandom prg;
        try {
            prg = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException("SHA1PRNG not available", ex);
        }
        prg.setSeed(hashValue.toByteArray());
        BigInteger computedE;
        do {
            computedE = new BigInteger(q.bitLength(), prg);
        } while (computedE.compareTo(BigInteger.ZERO) <= 0 || computedE.compareTo(q) >= 0);
        System.out.println("  Computed challenge e' from PRG: " + computedE);

        // Step 4. The proof is valid if the computed challenge matches the one in the
        // proof.
        boolean isValid = computedE.equals(proof.getChallenge());
        System.out.println("  DLEQ proof verification result: " + isValid);
        return isValid;
    }
}
