package kz.edu.securecloud.repository;
import java.sql.*;
import java.util.*;
public abstract class JdbcDao<T> implements Repository<T> {
	protected final Database database;
	protected JdbcDao(Database database) {
		this.database = Objects.requireNonNull(database);
	}
	protected abstract T mapRow(ResultSet row) throws SQLException;
	protected List<T> query(String sql, Object... args) {
		try (Connection c = database.open(); PreparedStatement p = c.prepareStatement(sql)) {
			for (int i = 0; i < args.length; i++)
				p.setObject(i + 1, args[i]);
			try (ResultSet r = p.executeQuery()) {
				List<T> result = new ArrayList<>();
				while (r.next())
					result.add(mapRow(r));
				return List.copyOf(result);
			}
		} catch (SQLException e) {
			throw new IllegalStateException("Database query failed", e);
		}
	}
}