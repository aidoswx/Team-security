package kz.edu.securecloud.crypto;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
/**
 * Client-only key vault and per-file RSA envelopes. Never send passwords or
 * private keys to the server.
 */
public final class KeyManagementService {
	private static final byte[] VAULT_AAD = "secure-cloud/private-key/v1".getBytes(StandardCharsets.UTF_8);
	private final EncryptionService crypto = new EncryptionService();
	private final RsaKeyService rsa = new RsaKeyService();
	public KeyPair generate() {
		return rsa.generateKeyPair();
	}
	public byte[] protectPrivateKey(PrivateKey key, char[] password) {
		byte[] raw = key.getEncoded();
		try {
			return EncryptedFileCodec.encode(crypto.encrypt(raw, password, VAULT_AAD));
		} finally {
			Arrays.fill(raw, (byte) 0);
		}
	}
	public PrivateKey unlockPrivateKey(byte[] vault, char[] password) {
		byte[] raw = crypto.decrypt(EncryptedFileCodec.decode(vault), password, VAULT_AAD);
		try {
			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw));
		} catch (GeneralSecurityException e) {
			throw new CryptoException("Invalid private key", e);
		} finally {
			Arrays.fill(raw, (byte) 0);
		}
	}
	public PublicKey readPublicKey(byte[] encoded) {
		try {
			return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
		} catch (GeneralSecurityException e) {
			throw new CryptoException("Invalid public key", e);
		}
	}
	public String fingerprint(PublicKey key) {
		return crypto.sha256Hex(key.getEncoded());
	}
	public byte[] wrapFileKey(byte[] encoded, char[] filePassword, PublicKey recipient, byte[] aad) {
		EncryptedPayload payload = EncryptedFileCodec.decode(encoded);
		// Authenticate the file/password before creating an envelope.
		byte[] plaintext = crypto.decrypt(payload, filePassword, aad);
		Arrays.fill(plaintext, (byte) 0);
		return rsa.wrap(crypto.deriveKey(filePassword, payload.salt()), recipient);
	}
	public byte[] openSharedFile(byte[] encoded, byte[] wrappedKey, PrivateKey recipient, byte[] aad) {
		return crypto.decryptWithKey(EncryptedFileCodec.decode(encoded), rsa.unwrap(wrappedKey, recipient), aad);
	}
}