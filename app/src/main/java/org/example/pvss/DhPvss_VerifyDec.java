package org.example.pvss;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Verification of a decryption share for DHPVSS.
 */
public class DhPvss_VerifyDec {

    /**
     * Verifies that A_i is a correct decryption of C_i under the ephemeral key E_i.
     * It recomputes Δ_i = C_i - A_i and then checks a DLEQ proof that:
     * E_i = G^{x} and Δ_i = pkD^{x}
     * for the same x.
     *
     * @param ctx       PVSS context (includes G, alphas, dual-code coeffs, order)
     * @param pkD       Dealer's public key = G·skD
     * @param E_i       Participant's ephemeral public key = G·skE
     * @param C_i       Encrypted share = A_i + skD·E_i
     * @param A_i       Decryption share recovered = C_i - skE·pkD
     * @param dleqProof The DLEQ proof object
     * @return true if the proof verifies, false otherwise
     */
    public static boolean verifyDec(
            DhPvssContext ctx,
            ECPoint pkD,
            ECPoint E_i,
            ECPoint C_i,
            ECPoint A_i,
            NizkDlEqProof dleqProof) {
        // Compute Δ_i = C_i - A_i
        ECPoint delta = C_i.subtract(A_i).normalize();

        // Verify the DLEQ proof: prove knowledge of x such that
        // E_i = G^x and delta = pkD^x
        return NizkDlEqProof.verifyProof(
                ctx,
                pkD, // base pkD
                E_i, // h1 = G^x
                delta, // h2 = pkD^x
                dleqProof // proof of same exponent
        );
    }
}
