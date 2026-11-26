package kz.edu.securecloud.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

@Service
public class EncryptionService {

	public static final int SALT_BYTES = 16;
	public static final int IV_BYTES = 12;
	public static final int SHA_256_BYTES = 32;
	public static final int GCM_TAG_BITS = 128;
	public static final int KEY_BITS = 256;
	public static final int PBKDF2_ITERATIONS = 210_000;

	private static final String CIPHER = "AES/GCM/NoPadding";
	private static final String KDF = "PBKDF2WithHmacSHA256";
	private static final String AES = "AES";

	private final SecureRandom secureRandom;

	public EncryptionService() {
		this(new SecureRandom());
	}

	EncryptionService(SecureRandom secureRandom) {
		this.secureRandom = Objects.requireNonNull(secureRandom);
	}

	public EncryptedPayload encrypt(byte[] plaintext, char[] password, byte[] associatedData) {
		Objects.requireNonNull(plaintext, "plaintext must not be null");
		validatePassword(password);

		byte[] salt = randomBytes(SALT_BYTES);
		byte[] iv = randomBytes(IV_BYTES);
		SecretKey key = deriveKey(password, salt);

		try {
			Cipher cipher = Cipher.getInstance(CIPHER);
			cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
			updateAssociatedData(cipher, associatedData);
			byte[] ciphertext = cipher.doFinal(plaintext);
			return new EncryptedPayload(salt, iv, ciphertext, sha256(ciphertext));
		} catch (GeneralSecurityException exception) {
			throw new CryptoException("Unable to encrypt the file", exception);
		}
	}

	public byte[] decrypt(EncryptedPayload payload, char[] password, byte[] associatedData) {
		Objects.requireNonNull(payload, "payload must not be null");
		validatePassword(password);
		validatePayload(payload);

		SecretKey key = deriveKey(password, payload.salt());
		return decryptWithKey(payload, key, associatedData);
	}
	public byte[] decryptWithKey(EncryptedPayload payload, SecretKey key, byte[] associatedData) {
		Objects.requireNonNull(payload);
		Objects.requireNonNull(key);
		validatePayload(payload);
		try {
			Cipher cipher = Cipher.getInstance(CIPHER);
			cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, payload.iv()));
			updateAssociatedData(cipher, associatedData);
			byte[] plaintext = cipher.doFinal(payload.ciphertext());
			if (!MessageDigest.isEqual(payload.ciphertextSha256(), sha256(payload.ciphertext()))) {
				Arrays.fill(plaintext, (byte) 0);
				throw new CryptoException("File integrity verification failed");
			}
			return plaintext;
		} catch (CryptoException exception) {
			throw exception;
		} catch (GeneralSecurityException exception) {
			throw new CryptoException("Unable to decrypt the file: wrong password or modified data");
		}
	}

	public SecretKey deriveKey(char[] password, byte[] salt) {
		validatePassword(password);
		Objects.requireNonNull(salt, "salt must not be null");
		if (salt.length != SALT_BYTES) {
			throw new IllegalArgumentException("Salt must contain exactly " + SALT_BYTES + " bytes");
		}

		PBEKeySpec keySpec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS);
		try {
			byte[] encoded = SecretKeyFactory.getInstance(KDF).generateSecret(keySpec).getEncoded();
			try {
				return new SecretKeySpec(encoded, AES);
			} finally {
				Arrays.fill(encoded, (byte) 0);
			}
		} catch (GeneralSecurityException exception) {
			throw new CryptoException("Unable to derive the encryption key", exception);
		} finally {
			keySpec.clearPassword();
		}
	}

	public byte[] sha256(byte[] data) {
		Objects.requireNonNull(data, "data must not be null");
		try {
			return MessageDigest.getInstance("SHA-256").digest(data);
		} catch (NoSuchAlgorithmException exception) {
			throw new CryptoException("SHA-256 is unavailable", exception);
		}
	}

	public String sha256Hex(byte[] data) {
		return HexFormat.of().formatHex(sha256(data));
	}

	public byte[] associatedData(String ownerId, String fileName, int version) {
		Objects.requireNonNull(ownerId, "ownerId must not be null");
		Objects.requireNonNull(fileName, "fileName must not be null");
		if (version < 1) {
			throw new IllegalArgumentException("Version must be positive");
		}
		return (ownerId + "\n" + fileName + "\n" + version).getBytes(StandardCharsets.UTF_8);
	}

	private byte[] randomBytes(int length) {
		byte[] value = new byte[length];
		secureRandom.nextBytes(value);
		return value;
	}

	private static void updateAssociatedData(Cipher cipher, byte[] associatedData) {
		if (associatedData != null && associatedData.length > 0) {
			cipher.updateAAD(associatedData);
		}
	}

	private static void validatePassword(char[] password) {
		Objects.requireNonNull(password, "password must not be null");
		if (password.length < 8) {
			throw new IllegalArgumentException("Password must contain at least 8 characters");
		}
	}

	private static void validatePayload(EncryptedPayload payload) {
		if (payload.salt().length != SALT_BYTES) {
			throw new IllegalArgumentException("Invalid salt length");
		}
		if (payload.iv().length != IV_BYTES) {
			throw new IllegalArgumentException("Invalid IV length");
		}
		if (payload.ciphertextSha256().length != SHA_256_BYTES) {
			throw new IllegalArgumentException("Invalid SHA-256 length");
		}
		if (payload.ciphertext().length < GCM_TAG_BITS / Byte.SIZE) {
			throw new IllegalArgumentException("Ciphertext is too short");
		}
	}
}
