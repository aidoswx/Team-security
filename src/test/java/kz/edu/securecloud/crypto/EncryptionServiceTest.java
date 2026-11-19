package kz.edu.securecloud.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class EncryptionServiceTest {

    private EncryptionService service;
    private char[] password;
    private byte[] aad;

    @BeforeEach
    void setUp() {
        service = new EncryptionService();
        password = "correct horse battery staple".toCharArray();
        aad = service.associatedData("alice", "report.txt", 1);
    }

    @Test
    void encryptAndDecryptRoundTrip() {
        byte[] plaintext = "confidential content".getBytes(StandardCharsets.UTF_8);

        EncryptedPayload payload = service.encrypt(plaintext, password, aad);

        assertThat(service.decrypt(payload, password, aad)).isEqualTo(plaintext);
    }

    @Test
    void encryptionDoesNotExposePlaintext() {
        byte[] plaintext = "visible secret".getBytes(StandardCharsets.UTF_8);

        EncryptedPayload payload = service.encrypt(plaintext, password, aad);

        assertThat(payload.ciphertext()).isNotEqualTo(plaintext);
        assertThat(new String(payload.ciphertext(), StandardCharsets.UTF_8)).doesNotContain("visible secret");
    }

    @Test
    void repeatedEncryptionUsesFreshSaltAndIv() {
        byte[] plaintext = "same content".getBytes(StandardCharsets.UTF_8);

        EncryptedPayload first = service.encrypt(plaintext, password, aad);
        EncryptedPayload second = service.encrypt(plaintext, password, aad);

        assertThat(first.salt()).isNotEqualTo(second.salt());
        assertThat(first.iv()).isNotEqualTo(second.iv());
        assertThat(first.ciphertext()).isNotEqualTo(second.ciphertext());
    }

    @Test
    void wrongPasswordIsRejected() {
        EncryptedPayload payload = service.encrypt("secret".getBytes(StandardCharsets.UTF_8), password, aad);

        assertThatThrownBy(() -> service.decrypt(payload, "incorrect password".toCharArray(), aad))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("wrong password or modified data");
    }

    @Test
    void modifiedCiphertextIsRejectedByGcmTag() {
        EncryptedPayload payload = service.encrypt("secret".getBytes(StandardCharsets.UTF_8), password, aad);
        byte[] modified = payload.ciphertext();
        modified[0] ^= 1;
        EncryptedPayload tampered = new EncryptedPayload(
                payload.salt(), payload.iv(), modified, payload.plaintextSha256());

        assertThatThrownBy(() -> service.decrypt(tampered, password, aad))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void differentAssociatedDataIsRejected() {
        EncryptedPayload payload = service.encrypt("secret".getBytes(StandardCharsets.UTF_8), password, aad);
        byte[] differentAad = service.associatedData("bob", "report.txt", 1);

        assertThatThrownBy(() -> service.decrypt(payload, password, differentAad))
                .isInstanceOf(CryptoException.class);
    }

    @Test
    void modifiedPlaintextHashIsRejected() {
        EncryptedPayload payload = service.encrypt("secret".getBytes(StandardCharsets.UTF_8), password, aad);
        byte[] modifiedHash = payload.plaintextSha256();
        modifiedHash[0] ^= 1;
        EncryptedPayload tampered = new EncryptedPayload(
                payload.salt(), payload.iv(), payload.ciphertext(), modifiedHash);

        assertThatThrownBy(() -> service.decrypt(tampered, password, aad))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("integrity");
    }

    @Test
    void keyDerivationIsDeterministicForSameInputs() {
        byte[] salt = new byte[EncryptionService.SALT_BYTES];
        Arrays.fill(salt, (byte) 7);

        assertThat(service.deriveKey(password, salt).getEncoded())
                .isEqualTo(service.deriveKey(password, salt).getEncoded());
    }

    @Test
    void differentSaltProducesDifferentKey() {
        byte[] firstSalt = new byte[EncryptionService.SALT_BYTES];
        byte[] secondSalt = new byte[EncryptionService.SALT_BYTES];
        secondSalt[0] = 1;

        assertThat(service.deriveKey(password, firstSalt).getEncoded())
                .isNotEqualTo(service.deriveKey(password, secondSalt).getEncoded());
    }

    @Test
    void passwordMustBeAtLeastEightCharacters() {
        assertThatThrownBy(() -> service.encrypt(new byte[]{1}, "short".toCharArray(), aad))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 8");
    }

    @Test
    void saltLengthIsValidated() {
        assertThatThrownBy(() -> service.deriveKey(password, new byte[8]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Salt");
    }

    @Test
    void sha256UsesExpectedKnownValue() {
        assertThat(service.sha256Hex("abc".getBytes(StandardCharsets.UTF_8)))
                .isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void associatedDataBindsOwnerNameAndVersion() {
        assertThat(service.associatedData("alice", "report.txt", 2))
                .isEqualTo("alice\nreport.txt\n2".getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void associatedDataRejectsInvalidVersion() {
        assertThatThrownBy(() -> service.associatedData("alice", "report.txt", 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encryptedPayloadDefensivelyCopiesArrays() {
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        byte[] ciphertext = new byte[16];
        byte[] hash = new byte[32];
        EncryptedPayload payload = new EncryptedPayload(salt, iv, ciphertext, hash);

        salt[0] = 1;
        payload.iv()[0] = 1;

        assertThat(payload.salt()[0]).isZero();
        assertThat(payload.iv()[0]).isZero();
    }
}
