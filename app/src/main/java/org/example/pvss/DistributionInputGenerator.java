package org.example.pvss;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * *Helper method used in debugging in app, so probably redundant*
 * Prepares the inputs for the DHPVSS distribution phase.
 *
 * • Dealer key‐pair (sk_D, pk_D) with pk_D = G·sk_D
 * • Ephemeral participant keys {E_i, π_i} where E_i = G·sk_{E,i} and π_i is a
 * DL proof
 * • Secret point S ∈ 𝔾, namely S = s·G
 */
public class DistributionInputGenerator {

    /**
     * Builds a DistributionInput ≔ (dealerKP, {Eᵢ, πᵢ}_{i=1..n}, S) for DHPVSS.
     *
     * @param ctx the DHPVSS context pp = (𝔾, p, t, n, {α_i}, {v_i})
     * @return DistributionInput containing:
     *         • dealerKP = (sk_D, pk_D)
     *         • ephemeralKeys[i] = (E_i, π_i) for i∈[1..n], with E_i = G·sk_{E,i}
     *         • secret S = s·G ∈ 𝔾
     * @throws NoSuchAlgorithmException if the DL proof PRG is unavailable
     */
    public static DistributionInput generateDistributionInput(DhPvssContext ctx)
            throws NoSuchAlgorithmException {

        SecureRandom rnd = new SecureRandom();
        int n = ctx.getNumParticipants();

        // 1) Dealer key‐pair (sk_D, pk_D) ← Gen()
        DhKeyPair dealerKP = DhKeyPair.generate(ctx);

        // 2) For each i=1..n: generate ephemeral sk_{E,i} and E_i = G·sk_{E,i},
        // then π_i ← NIZK-DL proof that log_G(E_i) = sk_{E,i}.
        EphemeralKeyPublic[] ephemeralKeys = new EphemeralKeyPublic[n];
        for (int i = 0; i < n; i++) {
            DhKeyPair ephKP = DhKeyPair.generate(ctx);
            ECPoint E_i = ephKP.getPublic();

            // π_i: proof of DL for E_i = G·sk_{E,i}
            NizkDlProof π_i = NizkDlProof.generateProof(ctx, ephKP);

            ephemeralKeys[i] = new EphemeralKeyPublic(E_i, π_i);
        }

        // 3) Sample secret scalar s ← Z_p, compute S = s·G
        BigInteger p = ctx.getGroupParameters().getgroupOrd();
        BigInteger s;
        do {
            s = new BigInteger(p.bitLength(), rnd).mod(p);
        } while (s.equals(BigInteger.ZERO));
        ECPoint S = ctx.getGenerator().multiply(s).normalize();

        return new DistributionInput(dealerKP, ephemeralKeys, S);
    }
}
