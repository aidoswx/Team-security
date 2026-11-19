package kz.edu.securecloud.crypto;

import java.util.Arrays;
import java.util.Objects;

public record EncryptedPayload(
        byte[] salt,
        byte[] iv,
        byte[] ciphertext,
        byte[] plaintextSha256
) {
    public EncryptedPayload {
        salt = copy(salt, "salt");
        iv = copy(iv, "iv");
        ciphertext = copy(ciphertext, "ciphertext");
        plaintextSha256 = copy(plaintextSha256, "plaintextSha256");
    }

    @Override
    public byte[] salt() {
        return salt.clone();
    }

    @Override
    public byte[] iv() {
        return iv.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public byte[] plaintextSha256() {
        return plaintextSha256.clone();
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof EncryptedPayload that)) {
            return false;
        }
        return Arrays.equals(salt, that.salt)
                && Arrays.equals(iv, that.iv)
                && Arrays.equals(ciphertext, that.ciphertext)
                && Arrays.equals(plaintextSha256, that.plaintextSha256);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(salt);
        result = 31 * result + Arrays.hashCode(iv);
        result = 31 * result + Arrays.hashCode(ciphertext);
        result = 31 * result + Arrays.hashCode(plaintextSha256);
        return result;
    }

    private static byte[] copy(byte[] value, String name) {
        Objects.requireNonNull(value, name + " must not be null");
        return value.clone();
    }
}
