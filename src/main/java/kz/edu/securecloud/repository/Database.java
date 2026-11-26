package kz.edu.securecloud.repository;
import java.nio.file.*;
import java.sql.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
@Component
public final class Database {
	private final String url;
	public Database(@Value("${secure-storage.database:./data/storage.db}") String path) {
		try {
			Path file = Path.of(path).toAbsolutePath();
			Files.createDirectories(file.getParent());
			url = "jdbc:sqlite:" + file;
			try (Connection c = open(); Statement s = c.createStatement()) {
				s.execute("PRAGMA journal_mode=WAL");
				s.execute(
						"CREATE TABLE IF NOT EXISTS files(id TEXT,version INTEGER,owner TEXT NOT NULL,name TEXT NOT NULL,hash TEXT NOT NULL,size INTEGER NOT NULL,created TEXT NOT NULL,PRIMARY KEY(id,version))");
				s.execute(
						"CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,file_id TEXT,version INTEGER,action TEXT NOT NULL)");
				s.execute(
						"CREATE TABLE IF NOT EXISTS grants(file_id TEXT,owner TEXT NOT NULL,recipient TEXT,expires TEXT NOT NULL,PRIMARY KEY(file_id,recipient))");
			}
		} catch (Exception e) {
			throw new IllegalStateException("Cannot initialize SQLite", e);
		}
	}
	public Connection open() throws SQLException {
		Connection c = DriverManager.getConnection(url);
		try (Statement s = c.createStatement()) {
			s.execute("PRAGMA busy_timeout=5000");
			s.execute("PRAGMA foreign_keys=ON");
		}
		return c;
	}
	public static Database temporary() {
		try {
			return new Database(Files.createTempFile("securecloud-test-", ".db").toString());
		} catch (java.io.IOException e) {
			throw new IllegalStateException(e);
		}
	}
}