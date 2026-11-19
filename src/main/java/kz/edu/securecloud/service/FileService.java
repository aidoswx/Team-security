package kz.edu.securecloud.service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.UUID;
import kz.edu.securecloud.crypto.EncryptedFileCodec;
import kz.edu.securecloud.crypto.EncryptionService;
import kz.edu.securecloud.domain.AccessGrant;
import kz.edu.securecloud.domain.StoredFile;
import kz.edu.securecloud.repository.FileMetadataRepository;
import kz.edu.securecloud.storage.StorageService;
import org.springframework.stereotype.Service;

@Service
public class FileService {

    private static final int MAX_ENCODED_BYTES = EncryptedFileCodec.MAX_CIPHERTEXT_BYTES + 1024;

    private final FileMetadataRepository repository;
    private final StorageService storage;
    private final SharingService sharing;
    private final EncryptionService encryption;
    private final Clock clock;

    public FileService(
            FileMetadataRepository repository,
            StorageService storage,
            SharingService sharing,
            EncryptionService encryption,
            Clock clock) {
        this.repository = Objects.requireNonNull(repository);
        this.storage = Objects.requireNonNull(storage);
        this.sharing = Objects.requireNonNull(sharing);
        this.encryption = Objects.requireNonNull(encryption);
        this.clock = Objects.requireNonNull(clock);
    }

    public StoredFile uploadEncrypted(
            UUID requestedFileId,
            String ownerId,
            String originalFileName,
            int version,
            byte[] encryptedContent,
            String expectedSha256) {
        requireIdentifier(ownerId, "ownerId");
        String safeName = sanitizeFileName(originalFileName);
        Objects.requireNonNull(encryptedContent, "encryptedContent must not be null");
        if (encryptedContent.length == 0 || encryptedContent.length > MAX_ENCODED_BYTES) {
            throw new IllegalArgumentException("Encrypted file must contain 1 byte to 50 MB");
        }
        if (version < 1) {
            throw new IllegalArgumentException("Version must be positive");
        }

        EncryptedFileCodec.decode(encryptedContent);
        String actualSha256 = encryption.sha256Hex(encryptedContent);
        if (expectedSha256 == null
                || !actualSha256.equals(expectedSha256.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Encrypted file SHA-256 does not match");
        }

        UUID fileId = requestedFileId == null ? UUID.randomUUID() : requestedFileId;
        validateVersion(fileId, ownerId, version);

        StoredFile metadata = new StoredFile(
                fileId,
                version,
                ownerId,
                safeName,
                actualSha256,
                encryptedContent.length,
                clock.instant());

        storage.save(fileId, version, encryptedContent);
        try {
            return repository.save(metadata);
        } catch (RuntimeException exception) {
            storage.delete(fileId, version);
            throw exception;
        }
    }

    public FileDownload downloadEncrypted(UUID fileId, int version, String requesterId) {
        requireIdentifier(requesterId, "requesterId");
        StoredFile metadata = find(fileId, version);
        if (!sharing.hasAccess(fileId, metadata.ownerId(), requesterId)) {
            throw new SecurityException("Access to this file was denied");
        }
        byte[] encryptedContent = storage.load(fileId, version);
        String actualSha256 = encryption.sha256Hex(encryptedContent);
        if (!actualSha256.equals(metadata.encryptedSha256())) {
            throw new IllegalStateException("Stored encrypted file failed integrity verification");
        }
        return new FileDownload(metadata, encryptedContent);
    }

    public List<StoredFile> listVersions(UUID fileId, String requesterId) {
        requireIdentifier(requesterId, "requesterId");
        StoredFile latest = repository.findLatest(fileId)
                .orElseThrow(() -> new NoSuchElementException("File was not found"));
        if (!sharing.hasAccess(fileId, latest.ownerId(), requesterId)) {
            throw new SecurityException("Access to this file was denied");
        }
        return repository.findAllVersions(fileId);
    }

    public AccessGrant grantAccess(
            UUID fileId, String ownerId, String recipientId, Instant expiresAt) {
        StoredFile latest = repository.findLatest(fileId)
                .orElseThrow(() -> new NoSuchElementException("File was not found"));
        if (!latest.ownerId().equals(ownerId)) {
            throw new SecurityException("Only the file owner can grant access");
        }
        return sharing.grantAccess(fileId, ownerId, recipientId, expiresAt);
    }

    public void revokeAccess(UUID fileId, String ownerId, String recipientId) {
        StoredFile latest = repository.findLatest(fileId)
                .orElseThrow(() -> new NoSuchElementException("File was not found"));
        if (!latest.ownerId().equals(ownerId)) {
            throw new SecurityException("Only the file owner can revoke access");
        }
        sharing.revokeAccess(fileId, ownerId, recipientId);
    }

    private StoredFile find(UUID fileId, int version) {
        return repository.find(fileId, version)
                .orElseThrow(() -> new NoSuchElementException("File version was not found"));
    }

    private void validateVersion(UUID fileId, String ownerId, int version) {
        repository.findLatest(fileId).ifPresentOrElse(latest -> {
            if (!latest.ownerId().equals(ownerId)) {
                throw new SecurityException("A different user owns this file");
            }
            if (version != latest.version() + 1) {
                throw new IllegalArgumentException(
                        "New version must be " + (latest.version() + 1));
            }
        }, () -> {
            if (version != 1) {
                throw new IllegalArgumentException("The first file version must be 1");
            }
        });
    }

    static String sanitizeFileName(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            throw new IllegalArgumentException("File name must not be blank");
        }
        String normalized = fileName.replace('\\', '/');
        String result = normalized.substring(normalized.lastIndexOf('/') + 1).trim();
        if (result.isBlank() || result.length() > 255 || result.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("File name is invalid");
        }
        return result;
    }

    private static void requireIdentifier(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 100) {
            throw new IllegalArgumentException(name + " must contain 1 to 100 characters");
        }
    }
}
