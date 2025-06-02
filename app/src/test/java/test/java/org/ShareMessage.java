// package test.java.org;

// import java.math.BigInteger;
// import java.util.Arrays;

// import org.bouncycastle.math.ec.ECPoint;
// import org.example.napdkg.NizkDlEqProof;

// /**
// * A “row” of round‐1 data from dealer i to the bulletin board.
// */
// public class ShareMessage {
// private final int dealerIndex;
// private final ECPoint[] Cij; // encrypted shares Ci→j
// private final BigInteger[] Cht; // masked shares Ĉi→j
// private final ECPoint U; // SCRAPE U
// private final ECPoint V; // SCRAPE V
// private final NizkDlEqProof dleq; // proof that V = skE_i · U

// public ShareMessage(int dealerIndex,
// ECPoint[] Cij,
// BigInteger[] Cht,
// ECPoint U,
// ECPoint V,
// NizkDlEqProof dleq) {
// this.dealerIndex = dealerIndex;
// this.Cij = Cij;
// this.Cht = Cht;
// this.U = U;
// this.V = V;
// this.dleq = dleq;
// }

// public int getDealerIndex() {
// return dealerIndex;
// }

// public ECPoint[] getEncryptedShares() {
// return Cij;
// }

// public BigInteger[] getMaskedShares() {
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

// @Override
// public String toString() {
// return "ShareMessage[i=" + dealerIndex + ", Cij=" + Arrays.toString(Cij) +
// ", Cht=" + Arrays.toString(Cht) + ", U=" + U + ", V=" + V +
// ", proof=" + dleq + "]";
// }
// }
