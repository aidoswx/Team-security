package kz.edu.securecloud.storage;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Objects;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class FileSystemStorageService implements StorageService {

    private final Path root;

    public FileSystemStorageService(@Value("${secure-storage.root:./data/encrypted}") String root) {
        this.root = Path.of(Objects.requireNonNull(root)).toAbsolutePath().normalize();
        try {
            Files.createDirectories(this.root);
        } catch (IOException exception) {
            throw new StorageException("Unable to initialize encrypted storage", exception);
        }
    }

    @Override
    public void save(UUID fileId, int version, byte[] encryptedContent) {
        Objects.requireNonNull(encryptedContent, "encryptedContent must not be null");
        if (encryptedContent.length == 0) {
            throw new IllegalArgumentException("Encrypted content must not be empty");
        }

        Path destination = resolve(fileId, version);
        try {
            Files.createDirectories(destination.getParent());
            Files.write(destination, encryptedContent,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (java.nio.file.FileAlreadyExistsException exception) {
            throw new StorageException("This encrypted file version already exists");
        } catch (IOException exception) {
            throw new StorageException("Unable to save encrypted file", exception);
        }
    }

    @Override
    public byte[] load(UUID fileId, int version) {
        Path source = resolve(fileId, version);
        try {
            return Files.readAllBytes(source);
        } catch (NoSuchFileException exception) {
            throw new StorageException("Encrypted file was not found");
        } catch (IOException exception) {
            throw new StorageException("Unable to read encrypted file", exception);
        }
    }

    @Override
    public void delete(UUID fileId, int version) {
        try {
            Files.deleteIfExists(resolve(fileId, version));
        } catch (IOException exception) {
            throw new StorageException("Unable to delete encrypted file", exception);
        }
    }

    Path resolve(UUID fileId, int version) {
        Objects.requireNonNull(fileId, "fileId must not be null");
        if (version < 1) {
            throw new IllegalArgumentException("Version must be positive");
        }
        Path resolved = root.resolve(fileId.toString()).resolve(version + ".scv").normalize();
        if (!resolved.startsWith(root)) {
            throw new SecurityException("Invalid storage path");
        }
        return resolved;
    }
}
