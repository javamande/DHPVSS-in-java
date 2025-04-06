package org.example.pvss;

import java.math.BigInteger;



/**
 * A simple representation of a non-interactive zero-knowledge (NIZK) proof
 * for a discrete logarithm relation. Typically this proof contains two values:
 * a challenge and a response.
 */
public class NizkDlProof {
    private final BigInteger challenge; // private for anonomity/safety
    // Final = once the field is assigned a value (typically in the constructor), it
    // cannot be changed.
    // private final ensures that once the proof is constructed, its values remain
    // constant
    private final BigInteger response; // private for anonomity/safety

    /**
     * Constructs a NizkDlProof with the given challenge and response.
     *
     * @param challenge the challenge value (often computed via a hash) e
     * @param response  the response value computed as z = r - e * x mod order
     */

     //Constructor for NizkDlProof. 
    public NizkDlProof(BigInteger challenge, BigInteger response) {
        this.challenge = challenge;
        this.response = response;
    }

    public BigInteger getChallenge() {
        return challenge;
    }

    public BigInteger getResponse() {
        return response;
    }

    @Override // best practice to annotate methods that are intended to override a method from
              // a superclass.
    public String toString() {
        return "NizkDlProof{" +
                "challenge=" + challenge +
                ", response=" + response +
                '}';
    }

}
