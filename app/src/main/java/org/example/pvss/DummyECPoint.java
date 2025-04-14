package org.example.pvss;

// A dummy implementation of an elliptic curve point for testing purposes.
public class DummyECPoint {
    // The “value” represents the discrete logarithm with respect to a fixed
    // generator.
    private final java.math.BigInteger value;
    // The modulus (prime) over which the group is defined.
    private final java.math.BigInteger modulus;

    public DummyECPoint(java.math.BigInteger value, java.math.BigInteger modulus) {
        // Always reduce the value modulo the modulus.
        this.value = value.mod(modulus);
        this.modulus = modulus;
    }

    /**
     * Group addition: In the dummy group, addition is just modular addition.
     */
    public DummyECPoint add(DummyECPoint other) {
        if (!this.modulus.equals(other.modulus)) {
            throw new IllegalArgumentException("Modulus mismatch");
        }
        return new DummyECPoint(this.value.add(other.value).mod(modulus), modulus);
    }

    /**
     * Scalar multiplication: In the dummy group, multiplying by a scalar is just
     * modular multiplication.
     */
    public DummyECPoint multiply(java.math.BigInteger scalar) {
        return new DummyECPoint(this.value.multiply(scalar).mod(modulus), modulus);
    }

    /**
     * Returns a fixed generator for this dummy group.
     * For testing, we can simply choose a small integer as the generator.
     */
    public static DummyECPoint getGenerator(java.math.BigInteger modulus) {
        // In a real setup, G is specified by the curve.
        // For testing, we choose a fixed small value (e.g., 2) as the generator.
        return new DummyECPoint(java.math.BigInteger.valueOf(2), modulus);
    }

    /**
     * Returns the identity element of the group (the "point at infinity").
     * In our dummy group, we represent the identity by 0.
     */
    public static DummyECPoint infinity(java.math.BigInteger modulus) {
        return new DummyECPoint(java.math.BigInteger.ZERO, modulus);
    }

    public java.math.BigInteger getValue() {
        return value;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof DummyECPoint))
            return false;
        DummyECPoint that = (DummyECPoint) obj;
        return this.value.equals(that.value) && this.modulus.equals(that.modulus);
    }

    @Override
    public String toString() {
        return "DummyECPoint(" + value + ")";
    }
}
