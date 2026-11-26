package kz.edu.securecloud.repository;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import kz.edu.securecloud.domain.StoredFile;
import org.springframework.beans.factory.annotation.Autowired;
@org.springframework.stereotype.Repository
public class FileMetadataRepository extends JdbcDao<StoredFile> {
	public FileMetadataRepository() {
		this(Database.temporary());
	}
	@Autowired
	public FileMetadataRepository(Database database) {
		super(database);
	}
	@Override
	public StoredFile save(StoredFile f) {
		try (Connection c = database.open()) {
			c.setAutoCommit(false);
			try {
				try (PreparedStatement p = c.prepareStatement("INSERT INTO files VALUES(?,?,?,?,?,?,?)")) {
					p.setString(1, f.fileId().toString());
					p.setInt(2, f.version());
					p.setString(3, f.ownerId());
					p.setString(4, f.originalFileName());
					p.setString(5, f.encryptedSha256());
					p.setLong(6, f.encryptedSize());
					p.setString(7, f.createdAt().toString());
					p.executeUpdate();
				}
				try (PreparedStatement p = c
						.prepareStatement("INSERT INTO audit(file_id,version,action) VALUES(?,?,'UPLOAD')")) {
					p.setString(1, f.fileId().toString());
					p.setInt(2, f.version());
					p.executeUpdate();
				}
				c.commit();
				return f;
			} catch (SQLException e) {
				c.rollback();
				throw e;
			}
		} catch (SQLException e) {
			throw new IllegalStateException("Cannot save file metadata", e);
		}
	}
	@Override
	protected StoredFile mapRow(ResultSet r) throws SQLException {
		return new StoredFile(UUID.fromString(r.getString("id")), r.getInt("version"), r.getString("owner"),
				r.getString("name"), r.getString("hash"), r.getLong("size"), Instant.parse(r.getString("created")));
	}
	@Override
	public List<StoredFile> findAll() {
		return query("SELECT * FROM files ORDER BY id,version");
	}
	public Optional<StoredFile> find(UUID id, int version) {
		return query("SELECT * FROM files WHERE id=? AND version=?", id.toString(), version).stream().findFirst();
	}
	public Optional<StoredFile> findLatest(UUID id) {
		return query("SELECT * FROM files WHERE id=? ORDER BY version DESC LIMIT 1", id.toString()).stream()
				.findFirst();
	}
	public List<StoredFile> findAllVersions(UUID id) {
		return query("SELECT * FROM files WHERE id=? ORDER BY version", id.toString());
	}
}