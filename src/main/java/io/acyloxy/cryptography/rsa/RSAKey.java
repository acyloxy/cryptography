package io.acyloxy.cryptography.rsa;

import java.math.BigInteger;
import java.util.Random;

public record RSAKey(Type type, BigInteger exponent, BigInteger modulus) {
    public static RSAKeyPair generate(int length) {
        Random random = new Random();
        BigInteger p = BigInteger.probablePrime(length, random),
                q = BigInteger.probablePrime(length, random),
                n = p.multiply(q),
                phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e, d;
        int phiNLen = phiN.bitLength();
        while (true) {
            e = new BigInteger(random.nextInt(phiNLen / 2, phiNLen), random);
            try {
                d = e.modInverse(phiN);
                break;
            } catch (ArithmeticException ignored) {
            }
        }
        return new RSAKeyPair(new RSAKey(Type.PUBLIC, e, n), new RSAKey(Type.PRIVATE, d, n));
    }

    public byte[] apply(byte[] input) {
        if (input.length == 0) {
            throw new IllegalArgumentException("empty input");
        }
        if (input[0] == 0) {
            throw new IllegalArgumentException("input must start with non-zero value");
        }
        byte[] bytes;
        if (input[0] < 0) {
            bytes = new byte[input.length + 1];
            bytes[0] = 0;
            System.arraycopy(input, 0, bytes, 1, input.length);
        } else {
            bytes = input;
        }
        byte[] output = apply(new BigInteger(bytes)).toByteArray();
        if (output[0] == 0) {
            bytes = new byte[output.length - 1];
            System.arraycopy(output, 1, bytes, 0, bytes.length);
        } else {
            bytes = output;
        }
        return bytes;
    }

    public BigInteger apply(BigInteger input) {
        if (input.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("input must be larger than 0");
        }
        if (input.compareTo(modulus) >= 0) {
            throw new IllegalArgumentException("input too large");
        }
        return input.modPow(exponent, modulus);
    }

    public String toPrettyString() {
        StringBuilder builder = new StringBuilder();
        builder.append("-".repeat(25));
        switch (type) {
            case PUBLIC -> builder.append("RSA PUBLIC KEY").append("-".repeat(25));
            case PRIVATE -> builder.append("RSA PRIVATE KEY").append("-".repeat(24));
        }
        builder.append("\n");
        for (String line : split(exponent.toString(16), 64)) {
            builder.append(line).append("\n");
        }
        builder.append("-".repeat(64)).append("\n");
        for (String line : split(modulus.toString(16), 64)) {
            builder.append(line).append("\n");
        }
        builder.append("-".repeat(64));
        return builder.toString();
    }

    private String[] split(String s, int length) {
        int sLen = s.length();
        String[] fragments = new String[sLen / length + (sLen % length == 0 ? 0 : 1)];
        for (int i = 0; i < sLen; i += length) {
            if (sLen - i >= length) {
                fragments[i / length] = s.substring(i, i + length);
            } else {
                fragments[i / length] = s.substring(i, sLen);
            }
        }
        return fragments;
    }

    public enum Type {
        PUBLIC,

        PRIVATE
    }
}
