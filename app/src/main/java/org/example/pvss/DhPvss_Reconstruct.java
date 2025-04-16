
package org.example.pvss;

import org.bouncycastle.math.ec.ECPoint;

public class DhPvss_Reconstruct {

    /**
     * Reconstruction helper for DHPVSS: recovers dealer's secret S from a subset of
     * decrypted shares.
     */

    /**
     * Reconstructs the dealer's secret S from at least t+1 decrypted shares.
     * 
     * @param ctx     PVSS context (holds alphas, threshold, etc.)
     * @param shares  array of decrypted shares A_i = S + m(α_i)·G
     * @param indices corresponding evaluation-point indices (1-based)
     * @return the reconstructed secret point S
     */
    public static ECPoint reconstruct(
            DhPvssContext ctx,
            ECPoint[] shares,
            int[] indices) {
        // Leverage the existing reconstruction in GShamir_Share
        return GShamir_Share.reconstructSecretEC(ctx, shares, indices);
    }
}
