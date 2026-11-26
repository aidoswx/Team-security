package kz.edu.securecloud.crypto;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.*;
import static org.assertj.core.api.Assertions.*;
class RsaKeyServiceTest {
	static RsaKeyService service = new RsaKeyService();
	static KeyPair pair;
	@BeforeAll
	static void init() {
		pair = service.generateKeyPair();
	}
	@Test
	void wrapsAndRestoresAes256() {
		byte[] raw = new byte[32];
		new SecureRandom().nextBytes(raw);
		var aes = new SecretKeySpec(raw, "AES");
		assertThat(service.unwrap(service.wrap(aes, pair.getPublic()), pair.getPrivate()).getEncoded()).isEqualTo(raw);
	}
	@Test
	void wrongRecipientFails() {
		var other = service.generateKeyPair();
		byte[] wrapped = service.wrap(new SecretKeySpec(new byte[32], "AES"), pair.getPublic());
		assertThatThrownBy(() -> service.unwrap(wrapped, other.getPrivate())).isInstanceOf(CryptoException.class);
	}
	@Test
	void modifiedEnvelopeFails() {
		byte[] wrapped = service.wrap(new SecretKeySpec(new byte[32], "AES"), pair.getPublic());
		wrapped[5] ^= 1;
		assertThatThrownBy(() -> service.unwrap(wrapped, pair.getPrivate())).isInstanceOf(CryptoException.class);
	}
}