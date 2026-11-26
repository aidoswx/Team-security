package kz.edu.securecloud.repository;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import kz.edu.securecloud.domain.AccessGrant;
@org.springframework.stereotype.Repository
public class AccessGrantDao extends JdbcDao<AccessGrant> {
	public AccessGrantDao(Database db) {
		super(db);
	}
	protected AccessGrant mapRow(ResultSet r) throws SQLException {
		return new AccessGrant(UUID.fromString(r.getString("file_id")), r.getString("owner"), r.getString("recipient"),
				Instant.parse(r.getString("expires")));
	}
	public List<AccessGrant> findAll() {
		return query("SELECT * FROM grants");
	}
	public Optional<AccessGrant> find(UUID id, String recipient) {
		return query("SELECT * FROM grants WHERE file_id=? AND recipient=?", id.toString(), recipient).stream()
				.findFirst();
	}
	public AccessGrant save(AccessGrant g) {
		try (Connection c = database.open();
				PreparedStatement p = c.prepareStatement(
						"INSERT INTO grants VALUES(?,?,?,?) ON CONFLICT(file_id,recipient) DO UPDATE SET owner=excluded.owner,expires=excluded.expires")) {
			p.setString(1, g.fileId().toString());
			p.setString(2, g.ownerId());
			p.setString(3, g.recipientId());
			p.setString(4, g.expiresAt().toString());
			p.executeUpdate();
			return g;
		} catch (SQLException e) {
			throw new IllegalStateException("Cannot save grant", e);
		}
	}
	public void delete(UUID id, String owner, String recipient) {
		try (Connection c = database.open();
				PreparedStatement p = c
						.prepareStatement("DELETE FROM grants WHERE file_id=? AND owner=? AND recipient=?")) {
			p.setString(1, id.toString());
			p.setString(2, owner);
			p.setString(3, recipient);
			p.executeUpdate();
		} catch (SQLException e) {
			throw new IllegalStateException("Cannot revoke grant", e);
		}
	}
}