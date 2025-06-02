package org.example.napdkg.util;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;

public final class MaskedShareCHat {
  private static final String HASH_ALGO = "SHA-256";

  /** Dealer side: mask a₍i,j₎ into Ć₍i,j₎ = a ⊕ H′(A). */
  public static BigInteger maskShare(ECPoint A, BigInteger share, BigInteger order) {
    BigInteger h = hashPointToScalar(A, order);
    return share.xor(h);
  }

  /** Verifier side: recover a₍i,j₎ = Ć ⊕ H′(A). */
  public static BigInteger unmaskShare(ECPoint A, BigInteger cHat, BigInteger order) {
    BigInteger h = hashPointToScalar(A, order);
    return cHat.xor(h);
  }

  /** Hashes the *compressed* encoding of A into a scalar mod order. */
  private static BigInteger hashPointToScalar(ECPoint P, BigInteger order) {
    try {
      // 1) canonical, compressed form (33 bytes on secp256k1 / P-256)
      byte[] enc = P.normalize().getEncoded(true);
      // 2) SHA-256
      MessageDigest md = MessageDigest.getInstance(HASH_ALGO);
      byte[] digest = md.digest(enc);
      // 3) reduce into [0,order)
      return new BigInteger(1, digest).mod(order);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
