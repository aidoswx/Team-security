package kz.edu.securecloud.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Objects;

public final class EncryptedFileCodec {

	public static final int MAX_CIPHERTEXT_BYTES = 50 * 1024 * 1024;
	private static final int MAGIC = 0x53435632; // SCV2: ciphertext hash, no plaintext fingerprint
	private static final int HEADER_BYTES = Integer.BYTES * 5;

	private EncryptedFileCodec() {
	}

	public static byte[] encode(EncryptedPayload payload) {
		Objects.requireNonNull(payload, "payload must not be null");
		validateLengths(payload);

		try (ByteArrayOutputStream bytes = new ByteArrayOutputStream(HEADER_BYTES + payload.salt().length
				+ payload.iv().length + payload.ciphertextSha256().length + payload.ciphertext().length);
				DataOutputStream output = new DataOutputStream(bytes)) {
			output.writeInt(MAGIC);
			writeBytes(output, payload.salt());
			writeBytes(output, payload.iv());
			writeBytes(output, payload.ciphertextSha256());
			writeBytes(output, payload.ciphertext());
			return bytes.toByteArray();
		} catch (IOException exception) {
			throw new CryptoException("Unable to encode encrypted file", exception);
		}
	}

	public static EncryptedPayload decode(byte[] encoded) {
		Objects.requireNonNull(encoded, "encoded file must not be null");
		if (encoded.length < HEADER_BYTES + EncryptionService.SALT_BYTES + EncryptionService.IV_BYTES
				+ EncryptionService.SHA_256_BYTES + 16) {
			throw new CryptoException("Encrypted file is incomplete");
		}

		try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(encoded))) {
			if (input.readInt() != MAGIC) {
				throw new CryptoException("Unsupported encrypted file format");
			}
			byte[] salt = readBytes(input, EncryptionService.SALT_BYTES, EncryptionService.SALT_BYTES, "salt");
			byte[] iv = readBytes(input, EncryptionService.IV_BYTES, EncryptionService.IV_BYTES, "IV");
			byte[] hash = readBytes(input, EncryptionService.SHA_256_BYTES, EncryptionService.SHA_256_BYTES, "hash");
			byte[] ciphertext = readBytes(input, 16, MAX_CIPHERTEXT_BYTES, "ciphertext");
			if (input.available() != 0) {
				throw new CryptoException("Encrypted file contains trailing data");
			}
			return new EncryptedPayload(salt, iv, ciphertext, hash);
		} catch (EOFException exception) {
			throw new CryptoException("Encrypted file is incomplete");
		} catch (IOException exception) {
			throw new CryptoException("Unable to decode encrypted file", exception);
		}
	}

	private static void writeBytes(DataOutputStream output, byte[] value) throws IOException {
		output.writeInt(value.length);
		output.write(value);
	}

	private static byte[] readBytes(DataInputStream input, int minimum, int maximum, String name) throws IOException {
		int length = input.readInt();
		if (length < minimum || length > maximum) {
			throw new CryptoException("Invalid " + name + " length");
		}
		byte[] value = input.readNBytes(length);
		if (value.length != length)
			throw new EOFException();
		return value;
	}

	private static void validateLengths(EncryptedPayload payload) {
		if (payload.salt().length != EncryptionService.SALT_BYTES || payload.iv().length != EncryptionService.IV_BYTES
				|| payload.ciphertextSha256().length != EncryptionService.SHA_256_BYTES) {
			throw new IllegalArgumentException("Encrypted payload has an invalid header");
		}
		if (payload.ciphertext().length < 16 || payload.ciphertext().length > MAX_CIPHERTEXT_BYTES) {
			throw new IllegalArgumentException("Encrypted payload has an invalid ciphertext length");
		}
	}
}
