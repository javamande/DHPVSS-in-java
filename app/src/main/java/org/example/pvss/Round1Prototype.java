// package org.example.pvss;

// import java.math.BigInteger;
// import java.security.SecureRandom;
// import java.util.List;

// import org.bouncycastle.math.ec.ECPoint;

// public class Round1Prototype {

// public static class RoundTwoOutput {
// public final ECPoint[] Cij;
// public final BigInteger[] Chat;
// public final NizkDlEqProof proof;

// public RoundTwoOutput(ECPoint[] Cij, BigInteger[] Chat, NizkDlEqProof proof)
// {
// this.Cij = Cij;
// this.Chat = Chat;
// this.proof = proof;
// }
// }

// public static void main(String[] args) throws Exception {
// int n = 6, t = 3;
// SecureRandom rnd = new SecureRandom();

// // --- SETUP CONTEXT ---
// DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(
// GroupGenerator.generateGroup(), t, n);

// // --- IN‐MEMORY PBB & ROUND 1 EPHEMERAL PUBS ---
// InMemoryPbbClient pbb = new InMemoryPbbClient("http://localhost:3000");
// DhKeyPair[] ephKeys = new DhKeyPair[n];
// EphemeralKeyPublic[] pubs = new EphemeralKeyPublic[n];
// for (int i = 0; i < n; i++) {
// ephKeys[i] = DhKeyPair.generate(ctx);
// pubs[i] = new EphemeralKeyPublic(
// ephKeys[i].getPublic(),
// NizkDlProof.generateProof(ctx, ephKeys[i]));
// }
// pbb.publishAll(pubs);

// // verify all round-1 DLOG proofs
// @SuppressWarnings("unchecked")
// List<EphemeralKeyPublic> fetched = (List) pbb.getStored();
// for (int i = 0; i < n; i++) {
// EphemeralKeyPublic e = fetched.get(i);
// if (!NizkDlProof.verifyProof(ctx, e.getPublicKey(), e.getProof())) {
// throw new IllegalStateException("bad DLOG proof @ party " + (i + 1));
// }
// }
// System.out.println("Round 1 complete");

// // --- ROUND 2 SHARING (dealer = index 0) ---
// BigInteger p = ctx.getOrder();
// BigInteger[] r = new BigInteger[n];
// for (int i = 0; i < n; i++) {
// r[i] = new BigInteger(p.bitLength(), rnd).mod(p);
// }
// int me = 0; // dealer is party 1
// Share[] myShares = GShamirShareDKG.generateShares(ctx, r[me]);

// // fetch everyone’s ephemeral PKs
// ECPoint[] pkj = new ECPoint[n];
// for (int j = 0; j < n; j++) {
// pkj[j] = fetched.get(j).getPublicKey();
// }

// // 3) Mask each share & compute CHat
// ECPoint[] Cij = new ECPoint[n];
// BigInteger[] Chat = new BigInteger[n];
// BigInteger ski = ephKeys[me].getSecretKey();
// for (int j = 0; j < n; j++) {
// BigInteger aij = myShares[j].getai();
// ECPoint Aij = myShares[j].getAiPoint();
// ECPoint Ej = pkj[j];

// Cij[j] = Ej.multiply(ski).add(Aij).normalize();
// Chat[j] = MaskedShareCHat.compute(Cij[j], aij, ctx);
// }

// // 4) Derive the hash-stretch polynomial m*
// BigInteger[] mStar = HashingTools.deriveFirstRoundPoly(
// ctx,
// fetched.get(me).getPublicKey(),
// pkj, Cij, Chat, n, t);

// // 5) Build U and V via NAP-DKG “Lagrange-at-0” weights
// BigInteger[] alphas = ctx.getAlphas(); // [0, α₁…αₙ]
// BigInteger[] lambdas = ctx.getVjs(); // λ₁…λₙ from context

// ECPoint U = ctx.getGenerator().getCurve().getInfinity();
// ECPoint V = ctx.getGenerator().getCurve().getInfinity();
// for (int j = 0; j < n; j++) {
// BigInteger eval = EvaluationTools.evaluatePolynomial(
// mStar, alphas[j + 1], p);
// BigInteger weight = lambdas[j].multiply(eval).mod(p);

// U = U.add(pkj[j].multiply(weight)).normalize();
// V = V.add(Cij[j].multiply(weight)).normalize();
// }

// // 6) Raw check + DLEQ proof
// System.out.println("RAW check V==U^ski? " + V.equals(U.multiply(ski)));
// NizkDlEqProof prf = NizkDlEqProof.generateProof(ctx, U, pkj[me], V, ski);
// System.out.println("ROUND-2 DLEQ proof OK? " +
// NizkDlEqProof.verifyProof(ctx, U, pkj[me], V, prf));

// // 7) Publish RoundTwoOutput
// RoundTwoOutput out = new RoundTwoOutput(Cij, Chat, prf);
// pbb.publishAll(new RoundTwoOutput[] { out });
// System.out.println("Round 2 complete for party " + (me + 1));
// }
// }
