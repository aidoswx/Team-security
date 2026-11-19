package kz.edu.securecloud.repository;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import kz.edu.securecloud.domain.StoredFile;
import org.springframework.stereotype.Repository;

@Repository
public class FileMetadataRepository {

    private final ConcurrentMap<FileVersionKey, StoredFile> files = new ConcurrentHashMap<>();

    public StoredFile save(StoredFile file) {
        FileVersionKey key = new FileVersionKey(file.fileId(), file.version());
        if (files.putIfAbsent(key, file) != null) {
            throw new IllegalStateException("This file version already exists");
        }
        return file;
    }

    public Optional<StoredFile> find(UUID fileId, int version) {
        return Optional.ofNullable(files.get(new FileVersionKey(fileId, version)));
    }

    public Optional<StoredFile> findLatest(UUID fileId) {
        return findAllVersions(fileId).stream().max(Comparator.comparingInt(StoredFile::version));
    }

    public List<StoredFile> findAllVersions(UUID fileId) {
        return files.values().stream()
                .filter(file -> file.fileId().equals(fileId))
                .sorted(Comparator.comparingInt(StoredFile::version))
                .toList();
    }

    public void delete(UUID fileId, int version) {
        files.remove(new FileVersionKey(fileId, version));
    }

    private record FileVersionKey(UUID fileId, int version) {
    }
}
