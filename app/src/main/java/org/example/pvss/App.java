package org.example.pvss;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECPoint;

public class App {
    public static void main(String[] args) throws Exception {

        int lambda = 64; // e.g., 64-bit prime (for testin
        int t = 6;
        int n = 10;
        // Generate group parameters (safe prime p and subgroup generator G) and create
        // the PVSS context.
        GroupGenerator.GroupParameters groupParams = GroupGenerator.generateGroup();
        // Using helper that calls dhPvssSetup, which computes evaluation points
        // (alphas) and dual-code coefficients (v).
        DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(groupParams, t, n);

        System.out.println("=== PVSS Context ===");
        System.out.println("Prime modulus p: " + ctx.getOrder());
        System.out.println("Group generator G: " + ctx.getGenerator());
        System.out.println("Evaluation points (alphas): " + Arrays.toString(ctx.getAlphas()));
        System.out.println("Dual-code coefficients (v): " + Arrays.toString(ctx.getV()));
        System.out.println();

        // -----------------------------
        // 2. Dealer Key Generation
        // -----------------------------
        // For testing, we set a fixed dealer secret.
        BigInteger dealerSecret = BigInteger.valueOf(13);
        // Compute the dealer's public key: pk = G^(dealerSecret) mod p.
        ECPoint dealerPub = ctx.getGenerator().multiply(dealerSecret);
        DhKeyPair dealerKeyPair = new DhKeyPair(dealerSecret, dealerPub);
        System.out.println("Dealer Key Pair:");
        System.out.println("  Secret: " + dealerSecret);
        System.out.println("  Public: " + dealerPub);
        System.out.println();

        // -----------------------------
        // 3. Shamir Secret Sharing (SSS)
        // -----------------------------
        // Define a secret S to be shared. In the multiplicative setting,
        // we encode S as S = G^(s) mod p, where s is a secret scalar.
        BigInteger secretScalar = BigInteger.valueOf(7);
        ECPoint S = ctx.getGenerator().multiply(secretScalar);
        System.out.println("Secret S (to be shared): " + S);
        System.out.println();

        // Generate shares using SSS implementation (here, SSSStandard generates
        // shares as evaluations of m(X)=S + a1*X + ... + a_t*X^t).
        ECPoint[] shares = GShamir_Share.generateSharesEC(ctx, S);
        System.out.println("Generated Shares:");
        for (int i = 0; i < shares.length; i++) {
            System.out.println("  Share for participant " + (i + 1) + ": " + shares[i]);
        }
        System.out.println();

        // -----------------------------
        // 4. Distribution: Encryption of Shares & DLEQ Proof Generation
        // -----------------------------
        // For distribution, we need commitment keys for each participant.
        // For testing, we generate these as random elements in Z_p*.
        int numParticipants = ctx.getNumParticipants();
        BigInteger[] comKeys = new BigInteger[numParticipants];
        SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < numParticipants; i++) {
            BigInteger key;
            do {
                key = new BigInteger(ctx.getOrder().bitLength(), rnd);
            } while (key.compareTo(BigInteger.ZERO) <= 0 || key.compareTo(ctx.getOrder()) >= 0);
            comKeys[i] = key;
        }
        System.out.println("Commitment Keys:");
        System.out.println(Arrays.toString(comKeys));
        System.out.println();

        // Call the distribution phase which encrypts the shares and generates a DLEQ
        // proof.git
        // In the multiplicative setting, the encrypted share for participant i is
        // computed as:
        // C_i = A_i * (comKey[i])^(dealerSecret) mod p.
        DHPVSS_Dist.DistributionResult distResult = DHPVSS_Dist.distribute(ctx, comKeys,
                dealerKeyPair, S);

        // -----------------------------
        // 5. Distribution Verification
        // -----------------------------
        // Verify the distribution using the aggregated weighted products U and V and
        // the DLEQ proof.
        boolean distValid = DHPVSSDistributionVerifier.dhPvssDistributeVerify(ctx,
                distResult.getProof(),
                distResult.getEncryptedShares(),
                dealerKeyPair.getPublic(),
                comKeys);
        System.out.println("Distribution Verification Result: " + distValid);
        System.out.println();

        // -----------------------------
        // 6. Reconstruction of Secret via SSS
        // -----------------------------
        // For reconstruction, choose t+1 shares. Here we simply take the first t+1
        // shares.
        int[] indices = new int[t + 1];
        ECPoint[] selectedShares = new ECPoint[t + 1];
        for (int i = 0; i < t + 1; i++) {
            indices[i] = i + 1; // Participant indices 1,...,t+1.
            selectedShares[i] = shares[i];
        }
        ECPoint reconstructed = GShamir_Share.reconstructSecretEC(ctx, selectedShares, indices);
        System.out.println("Reconstructed Secret S: " + reconstructed);
        System.out.println("Original Secret S:      " + S);
    }
}
