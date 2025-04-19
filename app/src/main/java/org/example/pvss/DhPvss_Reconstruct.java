package org.example.pvss;

import org.bouncycastle.math.ec.ECPoint;

public class DhPvss_Reconstruct {

    /**
     * Reconstruct the dealer’s secret S ∈ 𝔾 from a qualified subset of decrypted
     * shares.
     *
     * In DHPVSS each share is of the form
     * Aᵢ = S + m(αᵢ)·G
     * where m(X) is the dealer’s random Shamir polynomial with m(α₀)=0.
     *
     * Given t+1 shares {Aᵢ : i ∈ I} at evaluation points {αᵢ : i ∈ I},
     * the secret S is recovered via Lagrange interpolation at 0:
     *
     * S = ∑_{i∈I} λᵢ · Aᵢ
     *
     * where
     * λᵢ = ∏_{j∈I, j≠i} (0 - αⱼ)/(αᵢ - αⱼ) mod p.
     *
     * @param ctx     the DHPVSS context containing {α₀…αₙ}, threshold t, group
     *                order p, and G
     * @param shares  the decrypted shares Aᵢ for i in I (each Aᵢ ∈ 𝔾)
     * @param indices the corresponding 1-based indices i ∈ I (so that αᵢ is known)
     * @return the reconstructed secret point S ∈ 𝔾
     */
    public static ECPoint reconstruct(
            DhPvssContext ctx,
            ECPoint[] shares,
            int[] indices) {
        // Delegate to our Shamir‑on‑EC implementation, which computes:
        // S = Σ_{i∈I} λᵢ · shares[k] at x=0
        return GShamir_Share.reconstructSecretEC(ctx, shares, indices);
    }
}
