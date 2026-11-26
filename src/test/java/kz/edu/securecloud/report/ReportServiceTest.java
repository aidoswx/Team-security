package kz.edu.securecloud.report;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import kz.edu.securecloud.domain.StoredFile;
import kz.edu.securecloud.repository.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;
class ReportServiceTest {
	@TempDir
	Path temp;
	FileMetadataRepository dao;
	ReportService service;
	@BeforeEach
	void init() {
		dao = new FileMetadataRepository(new Database(temp.resolve("test.db").toString()));
		service = new ReportService(dao);
	}
	void add(UUID id, int version, String owner, String name) {
		dao.save(new StoredFile(id, version, owner, name, "a".repeat(64), 10, Instant.EPOCH));
	}
	@Test
	void countsDistinctFilesAndGroupsExtensions() {
		UUID id = UUID.randomUUID();
		add(id, 1, "alice", "x.TXT");
		add(id, 2, "alice", "x.txt");
		var s = service.summarize("alice");
		assertThat(s.files()).isEqualTo(1);
		assertThat(s.versions()).isEqualTo(2);
		assertThat(s.encryptedBytes()).isEqualTo(20);
		assertThat(s.byExtension()).containsEntry("txt", 2L);
	}
	@Test
	void excludesOtherOwners() {
		add(UUID.randomUUID(), 1, "bob", "secret.txt");
		assertThat(service.owned("alice")).isEmpty();
		assertThat(new String(service.csv("alice"), StandardCharsets.UTF_8)).doesNotContain("secret");
	}
	@Test
	void escapesQuotesCommasAndFormulas() {
		add(UUID.randomUUID(), 1, "alice", "=SUM(1,2)\".txt");
		String csv = new String(service.csv("alice"), StandardCharsets.UTF_8);
		assertThat(csv).contains("\"'=SUM(1,2)\"\".txt\"");
	}
	@Test
	void emptySummaryIsValid() {
		assertThat(service.summarize("alice").files()).isZero();
		assertThat(service.summarize("alice").byExtension()).isEmpty();
	}
}