package io.acyloxy.cryptography.rsa;

public class RSA {
    private RSAKey publicKey;

    private RSAKey privateKey;

    public RSAKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAKey publicKey) {
        if (publicKey.type() != RSAKey.Type.PUBLIC) {
            throw new IllegalArgumentException("public key required");
        }
        this.publicKey = publicKey;
    }

    public RSAKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(RSAKey privateKey) {
        if (privateKey.type() != RSAKey.Type.PRIVATE) {
            throw new IllegalArgumentException("private key required");
        }
        this.privateKey = privateKey;
    }

    public void fromKeyPair(RSAKeyPair pair) {
        setPublicKey(pair.publicKey());
        setPrivateKey(pair.privateKey());
    }

    public byte[] encrypt(byte[] plaintext) {
        return publicKey.apply(plaintext);
    }

    public byte[] decrypt(byte[] ciphertext) {
        return privateKey.apply(ciphertext);
    }
}
