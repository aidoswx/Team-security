package kz.edu.securecloud.crypto;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.*;
/**
 * Wraps random AES keys, never whole files. Public keys must be authenticated
 * out of band.
 */
public final class RsaKeyService {
	public KeyPair generateKeyPair() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			g.initialize(3072);
			return g.generateKeyPair();
		} catch (GeneralSecurityException e) {
			throw new CryptoException("RSA generation failed", e);
		}
	}
	public byte[] wrap(SecretKey aes, PublicKey recipient) {
		if (!"AES".equals(aes.getAlgorithm()) || aes.getEncoded().length != 32)
			throw new IllegalArgumentException("AES-256 key required");
		try {
			return cipher(Cipher.ENCRYPT_MODE, recipient).doFinal(aes.getEncoded());
		} catch (GeneralSecurityException e) {
			throw new CryptoException("Key wrapping failed", e);
		}
	}
	public SecretKey unwrap(byte[] wrapped, PrivateKey recipient) {
		byte[] raw = null;
		try {
			raw = cipher(Cipher.DECRYPT_MODE, recipient).doFinal(wrapped);
			if (raw.length != 32)
				throw new CryptoException("Invalid AES key");
			return new SecretKeySpec(raw, "AES");
		} catch (GeneralSecurityException e) {
			throw new CryptoException("Key unwrapping failed", e);
		} finally {
			if (raw != null)
				java.util.Arrays.fill(raw, (byte) 0);
		}
	}
	private Cipher cipher(int mode, Key key) throws GeneralSecurityException {
		Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
		c.init(mode, key,
				new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
		return c;
	}
}