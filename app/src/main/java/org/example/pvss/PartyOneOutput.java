// package org.example.pvss;

// import java.math.BigInteger;

// import org.bouncycastle.math.ec.ECPoint;

// public class PartyOneOutput {
// private final ECPoint[] Cij; // encrypted shares
// private final BigInteger[] Cht; // one‐time‐pad masks
// private final ECPoint U, V; // the two combined points
// private final NizkDlEqProof dleq; // the U/V DLEQ proof

// /** constructor to initialize all fields */
// public PartyOneOutput(
// ECPoint[] Cij,
// BigInteger[] Cht,
// ECPoint U,
// ECPoint V,
// NizkDlEqProof dleq) {
// this.Cij = Cij;
// this.Cht = Cht;
// this.U = U;
// this.V = V;
// this.dleq = dleq;
// }

// // getters if you need them:
// public ECPoint[] getCij() {
// return Cij;
// }

// public BigInteger[] getCht() {
// return Cht;
// }

// public ECPoint getU() {
// return U;
// }

// public ECPoint getV() {
// return V;
// }

// public NizkDlEqProof getProof() {
// return dleq;
// }

// /**
// * Build the entire “round‐one” output for a single party,
// * but do NOT publish to the PBB—just return a PartyOneOutput.
// */
// public static PartyOneOutput computeFirstRoundForParty(
// DhPvssContext ctx,
// DhKeyPair myKey,
// DhKeyPair[] allKeys,
// BigInteger mySecret) throws Exception {
// int n = ctx.getNumParticipants();

// ECPoint myPub = myKey.getPublic();
// int me = -1;
// for (int i = 0; i < n; i++) {
// if (allKeys[i].getPublic().equals(myPub)) {
// me = i;
// break;
// }
// }
// if (me < 0) {
// throw new IllegalArgumentException("myKey not found in allKeys");
// }

// // 1) Shamir‐share
// Share[] shares = GShamirShareDKG.generateShares(ctx, mySecret);

// // 2) Encrypt + mask
// ECPoint[] Cij = new ECPoint[n];
// BigInteger[] Cht = new BigInteger[n];
// ECPoint[] Epks = new ECPoint[n];
// for (int j = 0; j < n; j++) {
// BigInteger ski = myKey.getSecretKey();
// ECPoint Ej = allKeys[j].getPublic();
// Cij[j] = Ej.multiply(ski).add(shares[j].getAiPoint()).normalize();
// Cht[j] = MaskedShareCHat.compute(shares[j].getAiPoint(), shares[j].getai(),
// ctx);
// Epks[j] = Ej;
// }

// // 3) derive m*(X)
// BigInteger[] mStar = HashingTools.deriveFirstRoundPoly(
// ctx,
// myKey.getPublic(),
// Epks, Cij, Cht,
// n,
// ctx.getThreshold());

// // 4) build U, V
// ECPoint U = ctx.getGenerator().getCurve().getInfinity();
// ECPoint V = U;
// BigInteger p = ctx.getOrder();
// BigInteger[] alphas = ctx.getAlphas();
// BigInteger[] vs = ctx.getV();
// for (int j = 0; j < n; j++) {
// BigInteger eval = EvaluationTools
// .evaluatePolynomial(mStar, alphas[j + 1], p);
// BigInteger coeff = vs[j].multiply(eval).mod(p);
// U = U.add(Epks[j].multiply(coeff)).normalize();
// V = V.add(Cij[j].multiply(coeff)).normalize();
// }

// // 5) DLEQ proof at *your* index
// NizkDlEqProof dleq = NizkDlEqProof.generateProof(
// ctx,
// U,
// myPub,
// V,
// myKey.getSecretKey());

// System.out.println(NizkDlEqProof.verifyProof(ctx, U, V, myPub, dleq));

// // 6) return
// return new PartyOneOutput(Cij, Cht, U, V, dleq);
// }
// }
