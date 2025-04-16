package org.example.pvss;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Demo application running the full DHPVSS PVSS protocol end-to-end:
 * 1) Setup
 * 2) Distribution (with proofs)
 * 3) Public verification of distribution
 * 4) Per-share decryption (with proofs)
 * 5) Public verification of each decryption
 * 6) Secret reconstruction
 */
public class App {
    public static void main(String[] args) throws Exception {

        for (int j = 1; j <= 10; j++) {
            // Use your setup function to create a PVSS context.
            // For example, choose threshold t and total participants n.
            SecureRandom rnd = new SecureRandom();
            int maxParticipants = 15;
            int n, t;
            do {
                n = 3 + rnd.nextInt(maxParticipants - 2); // ensure at least 3 participants
                // t in [1 .. n-2]
                t = 1 + rnd.nextInt(n - 2);
            } while (n - t - 2 <= 0);

            GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
            DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

            System.out.println("NO PARTICIPANTS : " + n);
            System.out.println("THRESHOLD : " + t);

            // Dealer keypair and secret
            DhKeyPair dealer = DhKeyPair.generate(ctx);
            BigInteger secretScalar = dealer.getSecretKey().mod(ctx.getOrder());
            ECPoint S = ctx.getGenerator().multiply(secretScalar);
            System.out.println("Dealer's secret S = " + S);

            // 2) Generate ephemeral keypairs + proofs
            DhKeyPair[] ephKeyPairs = new DhKeyPair[n];
            EphemeralKeyPublic[] epkWrapped = new EphemeralKeyPublic[n];
            for (int i = 0; i < n; i++) {
                DhKeyPair kp = DhKeyPair.generate(ctx);
                ephKeyPairs[i] = kp;
                NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
                epkWrapped[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
            }

            // 3) Distribution
            System.out.println("\n=== Distribution Phase ===");
            DHPVSS_Dist.DistributionResult distRes = DHPVSS_Dist.distribute(ctx, epkWrapped, dealer, S);
            ECPoint[] C = distRes.getEncryptedShares();
            System.out.println("Encrypted shares: " + C.length);

            // 4) Public verify distribution
            System.out.println("Verifying distribution proof...");
            ECPoint[] E = new ECPoint[n];
            for (int i = 0; i < n; i++) {
                E[i] = epkWrapped[i].getPublicKey();
            }
            boolean okDist = DHPVSS_Verify.verify(ctx,
                    dealer.getPublic(),
                    E, C,
                    distRes.getDleqProof());
            System.out.println("Distribution verification passed? " + okDist);

            // 5) Decrypt each share
            System.out.println("\n=== Decryption Phase ===");
            ECPoint[] A = new ECPoint[n];
            for (int i = 0; i < n; i++) {
                ECPoint E_i = epkWrapped[i].getPublicKey();
                BigInteger skE = ephKeyPairs[i].getSecretKey();
                ECPoint C_i = C[i];

                DhPvss_Decryption.DecryptionShare ds = DhPvss_Decryption.decShare(ctx, dealer.getPublic(), E_i,
                        skE, C_i);
                A[i] = ds.getShare();
            }

            // 6) Reconstruct secret from first t+1 shares
            System.out.println("\n=== Reconstruction Phase ===");
            int k = t + 1;
            ECPoint[] subsetShares = new ECPoint[k];
            int[] indices = new int[k];
            for (int i = 0; i < k; i++) {
                subsetShares[i] = A[i];
                indices[i] = i + 1;
            }
            ECPoint recovered = DhPvss_Reconstruct.reconstruct(ctx, subsetShares, indices);
            System.out.println("Reconstructed S = " + recovered);
            System.out.println(
                    "Reconstruction matches original? " + recovered.equals(S));
            System.out.println(" COMPLETED TEST " + j
                    + " OF 10 ");
        }
    }

}
