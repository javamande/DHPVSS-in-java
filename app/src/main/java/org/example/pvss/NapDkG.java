// package org.example.pvss;

// import java.io.IOException;
// import java.math.BigInteger;
// import java.security.SecureRandom;

// import org.bouncycastle.math.ec.ECPoint;

// public class NapDkG {
// @SuppressWarnings("static-access")
// public static void main(String[] args) throws Exception {

// // … build your epkWrapped array as before …

// PbbClient pbb = new InMemoryPbbClient("http://localhost:3000");

// int n = 8;
// int t = 5;

// GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
// DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);

// System.out.println("NO PARTICIPANTS : " + n);
// System.out.println("THRESHOLD : " + t);

// SecureRandom rnd = new SecureRandom();

// // Sample ski <-$ Z*p, compute Ei and publish pki on PBB.
// // 'generate' Generates a fresh key pair for the DHPVSS protocol.
// DhKeyPair[] ephKeyPairs = new DhKeyPair[n];
// EphemeralKeyPublic[] epkWrapped = new EphemeralKeyPublic[n];
// for (int i = 0; i < n; i++) {
// DhKeyPair kp = DhKeyPair.generate(ctx);
// ephKeyPairs[i] = kp;
// NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
// Boolean verify = NizkDlProof.verifyProof(ctx, kp.getPublic(), proof);

// System.out.println("Dl proof is " + verify);

// epkWrapped[i] = new EphemeralKeyPublic(i, kp.getPublic(), proof);
// }

// try {
// pbb.publishAll(epkWrapped);
// } catch (IOException | InterruptedException e) {
// e.printStackTrace();
// }

// // ri <-$ Z*p
// BigInteger[] r = new BigInteger[n];
// BigInteger p = ctx.getOrder();
// // for (int i = 0; i < n; i++) {
// // r[i] = new BigInteger(p.bitLength(), rnd).mod(p);
// // }
// r[0] = new BigInteger(p.bitLength(), rnd).mod(p);

// // System.out.println("Dealer's secret S = " + r);

// // String ok = sc.next();
// // if (ok.equalsIgnoreCase("yes") || ok.equalsIgnoreCase("Yes")) {
// // ok = sc.nextLine();
// // }

// // 2) Generate ephemeral keypairs + proofs

// // 3) Sharing
// System.out.println("\n=== Sharing Phase ===");
// Share[] shares = new Share[n];
// // for (int i = 0; i < n; i++) {
// // shares = GShamirShareDKG.generateShares(ctx, r[i]);
// // }
// shares = GShamirShareDKG.generateShares(ctx, r[0]);
// System.out.println("Shares lenght is " + shares.length);

// int k = t + 1;
// int[] indices = new int[k];
// for (int i = 0; i < k; i++) {
// indices[i] = i + 1;
// }
// System.out.println("Indices lenght is " + indices.length);

// // build a matching subset of exactly t+1 Share objects
// Share[] subset = new Share[k];
// for (int i = 0; i < k; i++) {
// subset[i] = shares[indices[i] - 1];
// }
// System.out.println(
// "Subset length = " + subset.length
// + ", indices length = " + indices.length);

// ECPoint reconstructedshares = GShamirShareDKG.reconstructSecretEC(ctx,
// subset, indices);

// System.out.println("Orginal Share = " +
// ctx.getGenerator().multiply(r[0]).normalize());
// System.out.println("Reconstructed Share = " +
// reconstructedshares.normalize());
// System.out.println(ctx.getGenerator().multiply(r[0]).equals(reconstructedshares));

// ECPoint[] Cij = new ECPoint[n];
// for (int i = 0; i < n; i++) {
// BigInteger skE = ephKeyPairs[i].getSecretKey();
// ECPoint Ej = ephKeyPairs[i].getPublic();
// Cij[i] = Ej.multiply(skE).add(shares[i].getAiPoint()); // Ci→j = skE · Ej +
// Ai→j
// }

// BigInteger[] CHat_ij = new BigInteger[n];
// for (int i = 0; i < n; i++) {
// ECPoint Cij_i = Cij[i]; // <-- make sure this is the *masked* point
// BigInteger ai = shares[i].getai();

// // compute and store
// BigInteger cHat = MaskedShareCHat.compute(Cij_i, ai, ctx);
// CHat_ij[i] = cHat;

// // optional sanity check
// BigInteger umasked = MaskedShareCHat.unmask(Cij_i, cHat, ctx);
// System.out.println("i=" + i
// + " original ai=" + ai
// + " unmasked=" + umasked
// + " ok?=" + ai.equals(umasked));
// }

// ECPoint[] pkj = new ECPoint[n];
// for (int i = 0; i < pkj.length; i++) {
// pkj[i] = ephKeyPairs[i].getPublic();
// }

// BigInteger[] hashMstar = HashingTools.deriveFirstRoundPoly(ctx, pkj[0], pkj,
// Cij, CHat_ij,
// n, t);

// // evaluate m* at each αᵢ → m*αᵢ, then partᵢ = vᵢ·m*αᵢ mod p
// BigInteger[] α = ctx.getAlphas();
// BigInteger[] v = ctx.getV();
// ECPoint U = ctx.getGenerator().getCurve().getInfinity();
// ECPoint V = ctx.getGenerator().getCurve().getInfinity();
// for (int i = 1; i <= n; i++) {
// BigInteger maskevalutation = EvaluationTools.evaluatePolynomial(hashMstar,
// α[i], p);
// BigInteger part = maskevalutation.multiply(v[i - 1]).mod(p);
// U = U.add(pkj[i - 1].multiply(part)).normalize();
// V = V.add(Cij[i - 1].multiply(part)).normalize();
// }

// for (int i = 0; i < n; i++) {
// // 5) prove V = sk_D·U via DLEQ
// NizkDlEqProof PfShi = NizkDlEqProof.generateProof(
// ctx, ephKeyPairs[i].getPublic(), U, V, ephKeyPairs[i].getSecretKey());
// // (optional) self‑check
// System.out.println("U = " + U);
// System.out.println("V = " + V);
// System.out.println("DLEQ ok? " +
// NizkDlEqProof.verifyProof(ctx, U, ephKeyPairs[i].getPublic(), V, PfShi));

// }

// }

// }
