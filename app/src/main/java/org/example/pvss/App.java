// package org.example.pvss;

// import java.math.BigInteger;
// import java.security.SecureRandom;

// public class App {
// public static void main(String[] args) throws Exception {
// int n = 20;
// int t = 10;

// GroupGenerator.GroupParameters gp = GroupGenerator.generateGroup();
// DhPvssContext ctx = DHPVSS_Setup.dhPvssSetup(gp, t, n);
// SecureRandom rnd = new SecureRandom();

// // one client per collection
// PbbClient pbb = new InMemoryPbbClient("http://localhost:3000");
// PbbClient ephClient = pbb; // we only need one PBB in memory
// PbbClient shareClient = pbb;

// System.out.println("NO PARTICIPANTS : " + n);
// System.out.println("THRESHOLD : " + t);

// // 1) make all n ephemeral keypairs + NIZK proofs
// DhKeyPair[] ephKeyPairs = new DhKeyPair[n];
// EphemeralKeyPublic[] epkWrapped = new EphemeralKeyPublic[n];
// for (int i = 0; i < n; i++) {
// DhKeyPair kp = DhKeyPair.generate(ctx);
// ephKeyPairs[i] = kp;
// NizkDlProof proof = NizkDlProof.generateProof(ctx, kp);
// epkWrapped[i] = new EphemeralKeyPublic(kp.getPublic(), proof);
// }

// // PUBLISH them to /ephemeralKeys
// ephClient.publishAll(epkWrapped);
// RoundOneService.publishEphemeralKeys(ephClient, ctx, ephKeyPairs,
// epkWrapped);
// // 2) sample your secret rᵢ’s
// BigInteger[] r = RoundOneService.sampleSecrets(ctx, rnd);

// // 3) run the sharing round (which will call shareClient.publishAll(...))
// RoundOneService.shareRoundOne(shareClient, ctx, ephKeyPairs, r);
// InMemoryPbbClient mem = (InMemoryPbbClient) ephClient;
// System.out.println("PBB store contents:");
// for (Object o : mem.getStored()) {
// System.out.println(" → " + o.getClass().getSimpleName() + ": " + o);
// }
// }
// }
