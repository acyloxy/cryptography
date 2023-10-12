package io.acyloxy.cryptography.rsa;

import java.math.BigInteger;
import java.util.Random;

public class Algorithm {
    public static boolean millerRabin(BigInteger n, int iterations) {
        BigInteger m = n.subtract(BigInteger.ONE);
        int k = m.getLowestSetBit();
        BigInteger q = m.shiftRight(k);
        Random random = new Random();
        for (int i = 0; i < iterations; i++) {
            BigInteger a;
            do {
                a = new BigInteger(n.bitLength(), random);
            } while (!(a.compareTo(BigInteger.ONE) > 0 && a.compareTo(n) < 0));
            for (int j = 0; j < k; j++) {
                BigInteger t = null;
                if (j == 0) {
                    t = modPow(a, q, n);
                    if (t.equals(BigInteger.ONE)) {
                        break;
                    }
                } else {
                    t = modPow(t, BigInteger.TWO, n);
                    if (t.equals(BigInteger.ONE)) {
                        return false;
                    }
                }
                if (t.equals(m)) {
                    break;
                }
            }
        }
        return true;
    }

    public static BigInteger[] extendedEuclidean(BigInteger a, BigInteger b) {
        BigInteger x1 = BigInteger.ONE, x2 = BigInteger.ZERO, y1 = BigInteger.ZERO, y2 = BigInteger.ONE;
        while (true) {
            BigInteger[] division = a.divideAndRemainder(b);
            BigInteger q = division[0], r = division[1];
            if (r.equals(BigInteger.ZERO)) {
                return new BigInteger[]{b, x2, y2};
            }
            a = b;
            b = r;
            BigInteger x = x1.subtract(q.multiply(x2)), y = y1.subtract(q.multiply(y2));
            x1 = x2;
            y1 = y2;
            x2 = x;
            y2 = y;
        }
    }

    public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger c = BigInteger.ZERO, f = BigInteger.ONE;
        for (int i = exponent.bitLength(); i >= 0; i--) {
            c = c.shiftLeft(1);
            f = f.multiply(f).mod(modulus);
            if (exponent.testBit(i)) {
                c = c.add(BigInteger.ONE);
                f = f.multiply(base).mod(modulus);
            }
        }
        return f;
    }
}
