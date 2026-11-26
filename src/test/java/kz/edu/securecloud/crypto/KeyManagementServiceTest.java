package kz.edu.securecloud.crypto;
import java.security.KeyPair;
import org.junit.jupiter.api.*;
import static org.assertj.core.api.Assertions.*;
class KeyManagementServiceTest {
	static KeyManagementService keys = new KeyManagementService();
	static KeyPair bob;
	static char[] vaultPassword = "bob-long-vault-password".toCharArray();
	@BeforeAll
	static void init() {
		bob = keys.generate();
	}
	@Test
	void privateKeyVaultRestoresCorrectKey() {
		byte[] vault = keys.protectPrivateKey(bob.getPrivate(), vaultPassword);
		assertThat(vault).isNotEqualTo(bob.getPrivate().getEncoded());
		assertThat(keys.unlockPrivateKey(vault, vaultPassword).getEncoded()).isEqualTo(bob.getPrivate().getEncoded());
	}
	@Test
	void wrongVaultPasswordFails() {
		byte[] vault = keys.protectPrivateKey(bob.getPrivate(), vaultPassword);
		assertThatThrownBy(() -> keys.unlockPrivateKey(vault, "wrong-password".toCharArray()))
				.isInstanceOf(CryptoException.class);
	}
	@Test
	void recipientOpensFileWithoutOwnerPassword() {
		EncryptionService crypto = new EncryptionService();
		byte[] aad = crypto.associatedData("alice", "secret.txt", 1);
		char[] filePassword = "alice-file-password".toCharArray();
		byte[] encoded = EncryptedFileCodec.encode(crypto.encrypt("secret".getBytes(), filePassword, aad));
		byte[] envelope = keys.wrapFileKey(encoded, filePassword, bob.getPublic(), aad);
		byte[] vault = keys.protectPrivateKey(bob.getPrivate(), vaultPassword);
		assertThat(keys.openSharedFile(encoded, envelope, keys.unlockPrivateKey(vault, vaultPassword), aad))
				.isEqualTo("secret".getBytes());
	}
	@Test
	void envelopeCannotOpenAnotherVersion() {
		EncryptionService crypto = new EncryptionService();
		char[] pass = "long-file-password".toCharArray();
		byte[] aad = crypto.associatedData("alice", "a", 1);
		byte[] first = EncryptedFileCodec.encode(crypto.encrypt(new byte[]{1}, pass, aad));
		byte[] envelope = keys.wrapFileKey(first, pass, bob.getPublic(), aad);
		byte[] second = EncryptedFileCodec
				.encode(crypto.encrypt(new byte[]{2}, pass, crypto.associatedData("alice", "a", 2)));
		assertThatThrownBy(
				() -> keys.openSharedFile(second, envelope, bob.getPrivate(), crypto.associatedData("alice", "a", 2)))
				.isInstanceOf(CryptoException.class);
	}
	@Test
	void publicKeyFingerprintSurvivesEncoding() {
		assertThat(keys.fingerprint(keys.readPublicKey(bob.getPublic().getEncoded())))
				.isEqualTo(keys.fingerprint(bob.getPublic())).hasSize(64);
	}
}