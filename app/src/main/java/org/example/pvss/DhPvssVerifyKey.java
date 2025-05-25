package org.example.pvss;

import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;

public class DhPvssVerifyKey {

    public static boolean verifyKey(DhPvssContext ctx, ECPoint pub, NizkDlProof proof) throws NoSuchAlgorithmException {

        return NizkDlProof.verifyProof(ctx, pub, proof);
    }

}
