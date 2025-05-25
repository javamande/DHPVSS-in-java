// package org.example.pvss;

// import java.math.BigInteger;
// import java.security.SecureRandom;

// import org.bouncycastle.math.ec.ECPoint;

// public class RoundOneService {

// private final PbbClient pbb;
// private final DhPvssContext ctx;

// public RoundOneService(PbbClient pbb, DhPvssContext ctx) {
// this.pbb = pbb;
// this.ctx = ctx;
// }

// public void publishEphemeralKeys(EphemeralKeyPublic[] epkWrapped)
// throws Exception {
// pbb.publish(epkWrapped);

// }

// /**
// * 1) Publish each party’s ephemeral key + DLOG proof.
// *
// * @throws Exception
// */
// // in RoundOneService.java
// public static void publishEphemeralKeys(
// PbbClient pbb,
// DhPvssContext ctx,
// DhKeyPair[] ephKeyPairs,
// EphemeralKeyPublic[] epkWrapped) throws Exception {
// // simply publish the raw array in one go:
// pbb.publish(epkWrapped);
// }

// /**
// * 2) Sample each party’s “dealer secret” r_i ∈ Z_p.
// */
// public static BigInteger[] sampleSecrets(
// DhPvssContext ctx,
// SecureRandom rnd) {
// int n = ctx.getNumParticipants();
// BigInteger p = ctx.getOrder();
// BigInteger[] r = new BigInteger[n];
// for (int i = 0; i < n; i++) {
// r[i] = new BigInteger(p.bitLength(), rnd).mod(p);
// }
// return r;
// }

// /**
// * 3) Each party i:
// * • turns r[i] into Shamir shares (A_{i→•}, a_{i→•})
// * • encrypts + masks them (Ci→j, Ĉi→j)
// * • derives m*(X) ← H(…)
// * • builds U,V and a DLEQ proof
// * • publishes a ShareMessage
// */
// public static void shareRoundOne(
// PbbClient pbb,
// DhPvssContext ctx,
// DhKeyPair[] ephKeyPairs,
// BigInteger[] r) throws Exception {
// int n = ctx.getNumParticipants();
// ShareMessage[] batch = new ShareMessage[n];
// for (int i = 0; i < n; i++) {
// // 3.1 Shamir
// Share[] shares = GShamirShareDKG.generateShares(ctx, r[i]);

// BigInteger recovered = MaskedShareCHat.unmask(shares[i].getAiPoint(),
// MaskedShareCHat.compute(shares[i].getAiPoint(), shares[i].getai(), ctx),
// ctx);
// System.out.println("original=" + shares[i].getai().toString(16));
// System.out.println("recovered=" + recovered.toString(16));
// assert shares[i].getai().equals(recovered);
// // 3.2 Encrypt + mask
// ECPoint[] Cij = new ECPoint[n];
// BigInteger[] Cht = new BigInteger[n];
// ECPoint[] Epks = new ECPoint[n];
// for (int j = 0; j < n; j++) {
// BigInteger ski = ephKeyPairs[i].getSecretKey();
// ECPoint Ej = ephKeyPairs[j].getPublic();
// Cij[j] = Ej.multiply(ski).add(shares[j].getAiPoint()).normalize();
// Cht[j] = MaskedShareCHat.compute(shares[j].getAiPoint(), shares[j].getai(),
// ctx);
// Epks[j] = Ej;
// }

// // 3.3 derive m* coefficients
// BigInteger[] mStar = HashingTools.deriveFirstRoundPoly(ctx,
// ephKeyPairs[i].getPublic(),
// Epks, Cij, Cht,
// ctx.getNumParticipants(),
// ctx.getThreshold());

// // 3.4 build U,V
// ECPoint U = ctx.getGenerator().getCurve().getInfinity();
// ECPoint V = U;
// BigInteger p = ctx.getOrder();
// BigInteger[] alphas = ctx.getAlphas();
// BigInteger[] vs = ctx.getV();
// for (int j = 0; j < n; j++) {
// BigInteger eval = EvaluationTools.evaluatePolynomial(mStar, alphas[j + 1],
// p);
// BigInteger coeff = vs[j].multiply(eval).mod(p);
// U = U.add(Epks[j].multiply(coeff)).normalize();
// V = V.add(Cij[j].multiply(coeff)).normalize();
// }

// // 3.5 DLEQ proof
// NizkDlEqProof dleq = NizkDlEqProof.generateProof(
// ctx, U, ephKeyPairs[i].getPublic(), V, ephKeyPairs[i].getSecretKey());

// // 3.6 publish one ShareMessage

// batch[i] = new ShareMessage(i, Cij, Cht, U, V, dleq);

// }
// pbb.publish(batch);
// }

// public static BigInteger[][] recoverSecretShares(
// DhPvssContext ctx,
// DhKeyPair[] ephKeyPairs,
// ShareMessage[] batch) {
// int n = ctx.getNumParticipants();

// // result[i][j] = the scalar aᵢ⟶ⱼ
// BigInteger[][] result = new BigInteger[n][n];

// for (int dealer = 0; dealer < n; dealer++) {
// ShareMessage m = batch[dealer];
// ECPoint[] Cij = m.getEncryptedShares();
// BigInteger[] masked = m.getMaskedShares();

// for (int receiver = 0; receiver < n; receiver++) {
// // 1) decrypt: Ai⟶j = Ci⟶j – ski⟶j * Ej
// BigInteger ski = ephKeyPairs[receiver].getSecretKey();
// ECPoint Ej = ephKeyPairs[receiver].getPublic();
// ECPoint Ai = Cij[receiver]
// .subtract(Ej.multiply(ski))
// .normalize();

// // 2) un‐mask the scalar
// // MaskedShareCHat.compute(ai, Ai) == masked
// // so we need the inverse of compute(·),
// // call it MaskedShareCHat.unmask(Ai, masked) ⟶ ai
// BigInteger ai = MaskedShareCHat.unmask(Ai, masked[receiver], ctx);
// result[dealer][receiver] = ai;
// }
// }

// return result;
// }

// }
