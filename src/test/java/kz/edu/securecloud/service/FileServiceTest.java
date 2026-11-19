package kz.edu.securecloud.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import kz.edu.securecloud.crypto.EncryptedFileCodec;
import kz.edu.securecloud.crypto.EncryptionService;
import kz.edu.securecloud.domain.StoredFile;
import kz.edu.securecloud.repository.FileMetadataRepository;
import kz.edu.securecloud.storage.FileSystemStorageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-19T12:00:00Z");
    private static final char[] PASSWORD = "strong test password".toCharArray();

    @TempDir
    Path tempDirectory;

    private EncryptionService encryption;
    private FileService service;

    @BeforeEach
    void setUp() {
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        encryption = new EncryptionService();
        service = new FileService(
                new FileMetadataRepository(),
                new FileSystemStorageService(tempDirectory.toString()),
                new SharingService(clock),
                encryption,
                clock);
    }

    @Test
    void ownerCanUploadAndDownloadEncryptedFile() {
        byte[] encoded = encrypted("hello", "report.txt", 1);

        StoredFile stored = upload(null, "alice", "report.txt", 1, encoded);

        assertThat(service.downloadEncrypted(stored.fileId(), 1, "alice").encryptedContent())
                .isEqualTo(encoded);
    }

    @Test
    void serverMetadataContainsEncryptedChecksumAndNotPlaintext() {
        byte[] encoded = encrypted("top secret", "report.txt", 1);

        StoredFile stored = upload(null, "alice", "report.txt", 1, encoded);

        assertThat(stored.encryptedSha256()).isEqualTo(encryption.sha256Hex(encoded));
        assertThat(stored.originalFileName()).isEqualTo("report.txt");
        assertThat(stored.encryptedSize()).isEqualTo(encoded.length);
    }

    @Test
    void pathSegmentsAreRemovedFromOriginalFileName() {
        byte[] encoded = encrypted("hello", "report.txt", 1);

        StoredFile stored = upload(null, "alice", "../../private/report.txt", 1, encoded);

        assertThat(stored.originalFileName()).isEqualTo("report.txt");
    }

    @Test
    void incorrectEncryptedChecksumIsRejected() {
        byte[] encoded = encrypted("hello", "report.txt", 1);

        assertThatThrownBy(() -> service.uploadEncrypted(
                null, "alice", "report.txt", 1, encoded, "0".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SHA-256");
    }

    @Test
    void malformedEncryptedContainerIsRejected() {
        byte[] malformed = new byte[100];

        assertThatThrownBy(() -> service.uploadEncrypted(
                null, "alice", "report.txt", 1, malformed, encryption.sha256Hex(malformed)))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void firstVersionMustBeOne() {
        byte[] encoded = encrypted("hello", "report.txt", 2);

        assertThatThrownBy(() -> upload(UUID.randomUUID(), "alice", "report.txt", 2, encoded))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("first");
    }

    @Test
    void nextSequentialVersionIsAccepted() {
        StoredFile first = upload(null, "alice", "report.txt", 1,
                encrypted("v1", "report.txt", 1));

        StoredFile second = upload(first.fileId(), "alice", "report.txt", 2,
                encrypted("v2", "report.txt", 2));

        assertThat(service.listVersions(first.fileId(), "alice"))
                .extracting(StoredFile::version)
                .containsExactly(1, 2);
        assertThat(second.fileId()).isEqualTo(first.fileId());
    }

    @Test
    void skippedVersionIsRejected() {
        StoredFile first = upload(null, "alice", "report.txt", 1,
                encrypted("v1", "report.txt", 1));

        assertThatThrownBy(() -> upload(first.fileId(), "alice", "report.txt", 3,
                encrypted("v3", "report.txt", 3)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("must be 2");
    }

    @Test
    void differentOwnerCannotCreateNewVersion() {
        StoredFile first = upload(null, "alice", "report.txt", 1,
                encrypted("v1", "report.txt", 1));

        assertThatThrownBy(() -> upload(first.fileId(), "mallory", "report.txt", 2,
                encrypted("v2", "report.txt", 2)))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void unrelatedUserCannotDownload() {
        StoredFile stored = upload(null, "alice", "report.txt", 1,
                encrypted("hello", "report.txt", 1));

        assertThatThrownBy(() -> service.downloadEncrypted(stored.fileId(), 1, "mallory"))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void activeRecipientCanDownload() {
        byte[] encoded = encrypted("hello", "report.txt", 1);
        StoredFile stored = upload(null, "alice", "report.txt", 1, encoded);
        service.grantAccess(stored.fileId(), "alice", "bob", NOW.plusSeconds(300));

        assertThat(service.downloadEncrypted(stored.fileId(), 1, "bob").encryptedContent())
                .isEqualTo(encoded);
    }

    @Test
    void nonOwnerCannotGrantAccess() {
        StoredFile stored = upload(null, "alice", "report.txt", 1,
                encrypted("hello", "report.txt", 1));

        assertThatThrownBy(() -> service.grantAccess(
                stored.fileId(), "mallory", "bob", NOW.plusSeconds(300)))
                .isInstanceOf(SecurityException.class);
    }

    @Test
    void revokedRecipientCannotDownload() {
        StoredFile stored = upload(null, "alice", "report.txt", 1,
                encrypted("hello", "report.txt", 1));
        service.grantAccess(stored.fileId(), "alice", "bob", NOW.plusSeconds(300));

        service.revokeAccess(stored.fileId(), "alice", "bob");

        assertThatThrownBy(() -> service.downloadEncrypted(stored.fileId(), 1, "bob"))
                .isInstanceOf(SecurityException.class);
    }

    private StoredFile upload(
            UUID fileId, String ownerId, String fileName, int version, byte[] encoded) {
        return service.uploadEncrypted(
                fileId, ownerId, fileName, version, encoded, encryption.sha256Hex(encoded));
    }

    private byte[] encrypted(String content, String fileName, int version) {
        byte[] aad = encryption.associatedData("alice", fileName, version);
        return EncryptedFileCodec.encode(encryption.encrypt(
                content.getBytes(StandardCharsets.UTF_8), PASSWORD, aad));
    }
}
