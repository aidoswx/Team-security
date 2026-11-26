package kz.edu.securecloud.storage;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileSystemStorageServiceTest {

	@TempDir
	Path tempDirectory;

	private FileSystemStorageService service;
	private UUID fileId;

	@BeforeEach
	void setUp() {
		service = new FileSystemStorageService(tempDirectory.toString());
		fileId = UUID.randomUUID();
	}

	@Test
	void saveAndLoadRoundTrip() {
		byte[] encrypted = new byte[]{1, 2, 3, 4};

		service.save(fileId, 1, encrypted);

		assertThat(service.load(fileId, 1)).isEqualTo(encrypted);
	}

	@Test
	void versionsUseDifferentPaths() {
		service.save(fileId, 1, new byte[]{1});
		service.save(fileId, 2, new byte[]{2});

		assertThat(service.load(fileId, 1)).containsExactly(1);
		assertThat(service.load(fileId, 2)).containsExactly(2);
	}

	@Test
	void overwriteIsRejected() {
		service.save(fileId, 1, new byte[]{1});

		assertThatThrownBy(() -> service.save(fileId, 1, new byte[]{2})).isInstanceOf(StorageException.class)
				.hasMessageContaining("already exists");
	}

	@Test
	void missingFileIsReported() {
		assertThatThrownBy(() -> service.load(fileId, 1)).isInstanceOf(StorageException.class)
				.hasMessageContaining("not found");
	}

	@Test
	void deleteRemovesStoredFile() {
		service.save(fileId, 1, new byte[]{1});

		service.delete(fileId, 1);

		assertThatThrownBy(() -> service.load(fileId, 1)).isInstanceOf(StorageException.class);
	}

	@Test
	void emptyContentIsRejected() {
		assertThatThrownBy(() -> service.save(fileId, 1, new byte[0])).isInstanceOf(IllegalArgumentException.class);
	}
}
