package kz.edu.securecloud.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EncryptedFileCodecTest {

	private EncryptedPayload payload;

	@BeforeEach
	void setUp() {
		EncryptionService service = new EncryptionService();
		payload = service.encrypt("codec test".getBytes(StandardCharsets.UTF_8), "long test password".toCharArray(),
				service.associatedData("alice", "file.txt", 1));
	}

	@Test
	void encodeAndDecodeRoundTrip() {
		assertThat(EncryptedFileCodec.decode(EncryptedFileCodec.encode(payload))).isEqualTo(payload);
	}

	@Test
	void encodedFileStartsWithScv2Magic() {
		byte[] encoded = EncryptedFileCodec.encode(payload);

		assertThat(Arrays.copyOf(encoded, 4)).isEqualTo(new byte[]{0x53, 0x43, 0x56, 0x32});
	}

	@Test
	void invalidMagicIsRejected() {
		byte[] encoded = EncryptedFileCodec.encode(payload);
		encoded[0] = 0;

		assertThatThrownBy(() -> EncryptedFileCodec.decode(encoded)).isInstanceOf(CryptoException.class)
				.hasMessageContaining("Unsupported");
	}

	@Test
	void incompleteFileIsRejected() {
		byte[] encoded = EncryptedFileCodec.encode(payload);

		assertThatThrownBy(() -> EncryptedFileCodec.decode(Arrays.copyOf(encoded, 12)))
				.isInstanceOf(CryptoException.class).hasMessageContaining("incomplete");
	}

	@Test
	void invalidSaltLengthIsRejected() {
		byte[] encoded = EncryptedFileCodec.encode(payload);
		ByteBuffer.wrap(encoded, 4, 4).putInt(15);

		assertThatThrownBy(() -> EncryptedFileCodec.decode(encoded)).isInstanceOf(CryptoException.class)
				.hasMessageContaining("salt");
	}

	@Test
	void trailingDataIsRejected() {
		byte[] encoded = EncryptedFileCodec.encode(payload);
		byte[] withTrailingByte = Arrays.copyOf(encoded, encoded.length + 1);

		assertThatThrownBy(() -> EncryptedFileCodec.decode(withTrailingByte)).isInstanceOf(CryptoException.class)
				.hasMessageContaining("trailing");
	}

	@Test
	void nullPayloadIsRejected() {
		assertThatThrownBy(() -> EncryptedFileCodec.encode(null)).isInstanceOf(NullPointerException.class);
	}
}
