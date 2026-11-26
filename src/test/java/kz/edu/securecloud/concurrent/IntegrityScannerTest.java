package kz.edu.securecloud.concurrent;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import kz.edu.securecloud.crypto.EncryptionService;
import kz.edu.securecloud.domain.StoredFile;
import kz.edu.securecloud.storage.StorageService;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
class IntegrityScannerTest {
	EncryptionService crypto = new EncryptionService();
	StoredFile file() {
		return new StoredFile(UUID.randomUUID(), 1, "alice", "a", "a".repeat(64), 1, Instant.EPOCH);
	}
	StorageService storage(byte[] bytes) {
		return new StorageService() {
			public void save(UUID id, int v, byte[] b) {
			}
			public void delete(UUID id, int v) {
			}
			public byte[] load(UUID id, int v) {
				return bytes;
			}
		};
	}
	@Test
	void detectsModification() {
		try (var s = new IntegrityScanner(storage(new byte[]{1}), crypto)) {
			assertThat(s.scan(List.of(file())).get(0).status()).isEqualTo(IntegrityScanner.Status.MODIFIED);
		}
	}
	@Test
	void validDigestPasses() {
		byte[] data = {1, 2};
		StoredFile f = new StoredFile(UUID.randomUUID(), 1, "a", "x", crypto.sha256Hex(data), 2, Instant.EPOCH);
		try (var s = new IntegrityScanner(storage(data), crypto)) {
			assertThat(s.scan(List.of(f)).get(0).status()).isEqualTo(IntegrityScanner.Status.OK);
		}
	}
	@Test
	void unreadableDoesNotAbortBatch() {
		StorageService bad = new StorageService() {
			public void save(UUID i, int v, byte[] b) {
			}
			public void delete(UUID i, int v) {
			}
			public byte[] load(UUID i, int v) {
				throw new IllegalStateException();
			}
		};
		try (var s = new IntegrityScanner(bad, crypto)) {
			assertThat(s.scan(List.of(file(), file()))).hasSize(2)
					.allMatch(r -> r.status() == IntegrityScanner.Status.UNREADABLE);
		}
	}
	@Test
	void actuallyRunsSimultaneously() {
		CountDownLatch entered = new CountDownLatch(2);
		Set<String> threads = ConcurrentHashMap.newKeySet();
		StorageService st = new StorageService() {
			public void save(UUID i, int v, byte[] b) {
			}
			public void delete(UUID i, int v) {
			}
			public byte[] load(UUID i, int v) {
				threads.add(Thread.currentThread().getName());
				entered.countDown();
				try {
					if (!entered.await(5, TimeUnit.SECONDS))
						throw new AssertionError("Not parallel");
				} catch (InterruptedException e) {
					throw new AssertionError(e);
				}
				return new byte[]{1};
			}
		};
		try (var s = new IntegrityScanner(st, crypto)) {
			assertThat(s.scan(List.of(file(), file()))).hasSize(2);
			assertThat(threads).hasSize(2);
		}
	}
}