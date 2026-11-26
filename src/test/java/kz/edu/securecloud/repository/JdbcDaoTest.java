package kz.edu.securecloud.repository;
import java.nio.file.Path;
import java.sql.*;
import java.time.Instant;
import java.util.UUID;
import kz.edu.securecloud.domain.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.assertj.core.api.Assertions.*;
class JdbcDaoTest {
	@TempDir
	Path temp;
	Database db;
	FileMetadataRepository dao;
	@BeforeEach
	void init() {
		db = new Database(temp.resolve("test.db").toString());
		dao = new FileMetadataRepository(db);
	}
	StoredFile file() {
		return new StoredFile(UUID.randomUUID(), 1, "alice", "x.txt", "a".repeat(64), 10, Instant.now());
	}
	@Test
	void persistsAcrossInstances() {
		StoredFile f = file();
		Repository<StoredFile> generic = dao;
		generic.save(f);
		assertThat(new FileMetadataRepository(new Database(temp.resolve("test.db").toString())).find(f.fileId(), 1))
				.contains(f);
	}
	@Test
	void rollbackIncludesMetadataWhenAuditFails() throws Exception {
		try (Connection c = db.open(); Statement s = c.createStatement()) {
			s.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'test'); END");
		}
		assertThatThrownBy(() -> dao.save(file())).isInstanceOf(IllegalStateException.class);
		assertThat(dao.findAll()).isEmpty();
	}
	@Test
	void duplicateCannotAddAudit() throws Exception {
		StoredFile f = file();
		dao.save(f);
		assertThatThrownBy(() -> dao.save(f)).isInstanceOf(IllegalStateException.class);
		try (Connection c = db.open();
				Statement s = c.createStatement();
				ResultSet r = s.executeQuery("SELECT count(*) FROM audit")) {
			assertThat(r.next()).isTrue();
			assertThat(r.getInt(1)).isEqualTo(1);
		}
	}
	@Test
	void grantsPersistAndRevoke() {
		AccessGrantDao grants = new AccessGrantDao(db);
		AccessGrant g = new AccessGrant(UUID.randomUUID(), "alice", "bob", Instant.now().plusSeconds(60));
		grants.save(g);
		assertThat(new AccessGrantDao(db).find(g.fileId(), "bob")).contains(g);
		grants.delete(g.fileId(), "alice", "bob");
		assertThat(grants.findAll()).isEmpty();
	}
	@Test
	void identifiersUseBoundParameters() {
		StoredFile f = new StoredFile(UUID.randomUUID(), 1, "a' OR 1=1--", "x", "a".repeat(64), 1, Instant.now());
		dao.save(f);
		assertThat(dao.findAll()).containsExactly(f);
	}
}