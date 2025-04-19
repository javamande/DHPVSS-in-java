package org.example.pvss;

import java.math.BigInteger;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * pp_EC = (𝔾, p, h)
 *
 * where
 * • 𝔾 is the elliptic‐curve subgroup of prime order p,
 * • p is the subgroup order,
 * • h is the cofactor (usually 1 for prime curves).
 *
 * We instantiate 𝔾 ← secp256r1 (aka prime256v1).
 */
public class GroupGenerator {
    /**
     * Runs the EC setup for YOSO‑DHPVSS.
     * 
     * @return pp_EC wrapped in GroupParameters
     */
    public static GroupParameters generateGroup() {
        X9ECParameters params = CustomNamedCurves.getByName("secp256r1");
        ECDomainParameters ec = new ECDomainParameters(
                params.getCurve(),
                params.getG(), // generator G ∈ 𝔾
                params.getN(), // order p = |𝔾|
                params.getH(), // cofactor h
                params.getSeed());
        return new GroupParameters(ec);
    }

    /**
     * Container for the EC subgroup 𝔾 and its prime order p.
     */
    public static class GroupParameters {
        private final ECDomainParameters ec;

        public GroupParameters(ECDomainParameters ecParams) {
            this.ec = ecParams;
        }

        /** @return G — the fixed generator of the subgroup 𝔾 */
        public ECPoint getG() {
            return ec.getG();
        }

        /** @return p — the prime order of 𝔾 (used as “p” in the paper) */
        public BigInteger getgroupOrd() {
            return ec.getN();
        }

        /** @return h — the cofactor of the curve (for completeness) */
        public BigInteger getCofactor() {
            return ec.getH();
        }

        /** @return the underlying ECDomainParameters */
        public ECDomainParameters getEcParams() {
            return ec;
        }
    }
}
