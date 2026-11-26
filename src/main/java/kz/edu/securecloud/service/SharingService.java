package kz.edu.securecloud.service;
import java.time.*;
import java.util.*;
import kz.edu.securecloud.domain.AccessGrant;
import kz.edu.securecloud.repository.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
@Service
public class SharingService {
	private final AccessGrantDao dao;
	private final Clock clock;
	public SharingService(Clock clock) {
		this(clock, new AccessGrantDao(Database.temporary()));
	}
	@Autowired
	public SharingService(Clock clock, AccessGrantDao dao) {
		this.clock = Objects.requireNonNull(clock);
		this.dao = dao;
	}
	public AccessGrant grantAccess(UUID id, String owner, String recipient, Instant expires) {
		requireIdentifier(owner, "ownerId");
		requireIdentifier(recipient, "recipientId");
		Objects.requireNonNull(expires);
		if (owner.equals(recipient))
			throw new IllegalArgumentException("Owner already has access");
		if (!expires.isAfter(clock.instant()))
			throw new IllegalArgumentException("Expiration time must be in the future");
		return dao.save(new AccessGrant(id, owner, recipient, expires));
	}
	public void revokeAccess(UUID id, String owner, String recipient) {
		requireIdentifier(owner, "ownerId");
		requireIdentifier(recipient, "recipientId");
		dao.find(id, recipient).ifPresent(g -> {
			if (!g.ownerId().equals(owner))
				throw new SecurityException("Only the file owner can revoke access");
		});
		dao.delete(id, owner, recipient);
	}
	public boolean hasAccess(UUID id, String owner, String requester) {
		requireIdentifier(owner, "ownerId");
		requireIdentifier(requester, "requesterId");
		if (owner.equals(requester))
			return true;
		return dao.find(id, requester).filter(g -> g.ownerId().equals(owner) && g.isActive(clock)).isPresent();
	}
	private static void requireIdentifier(String value, String name) {
		if (value == null || value.isBlank() || value.length() > 100)
			throw new IllegalArgumentException(name + " must contain 1 to 100 characters");
	}
}