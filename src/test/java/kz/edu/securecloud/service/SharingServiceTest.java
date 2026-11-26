package kz.edu.securecloud.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SharingServiceTest {

	private static final Instant NOW = Instant.parse("2026-11-19T12:00:00Z");

	private SharingService service;
	private UUID fileId;

	@BeforeEach
	void setUp() {
		service = new SharingService(Clock.fixed(NOW, ZoneOffset.UTC));
		fileId = UUID.randomUUID();
	}

	@Test
	void ownerAlwaysHasAccess() {
		assertThat(service.hasAccess(fileId, "alice", "alice")).isTrue();
	}

	@Test
	void recipientHasAccessAfterGrant() {
		service.grantAccess(fileId, "alice", "bob", NOW.plusSeconds(60));

		assertThat(service.hasAccess(fileId, "alice", "bob")).isTrue();
	}

	@Test
	void expiredGrantDoesNotProvideAccess() {
		MutableClock mutableClock = new MutableClock(NOW);
		SharingService mutableService = new SharingService(mutableClock);
		mutableService.grantAccess(fileId, "alice", "bob", NOW.plusSeconds(60));
		mutableClock.setInstant(NOW.plusSeconds(120));

		assertThat(mutableService.hasAccess(fileId, "alice", "bob")).isFalse();
	}

	@Test
	void pastExpirationIsRejected() {
		assertThatThrownBy(() -> service.grantAccess(fileId, "alice", "bob", NOW.minusSeconds(1)))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void ownerCannotShareWithSelf() {
		assertThatThrownBy(() -> service.grantAccess(fileId, "alice", "alice", NOW.plusSeconds(60)))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void revokeRemovesRecipientAccess() {
		service.grantAccess(fileId, "alice", "bob", NOW.plusSeconds(60));

		service.revokeAccess(fileId, "alice", "bob");

		assertThat(service.hasAccess(fileId, "alice", "bob")).isFalse();
	}

	@Test
	void differentOwnerCannotRevokeGrant() {
		service.grantAccess(fileId, "alice", "bob", NOW.plusSeconds(60));

		assertThatThrownBy(() -> service.revokeAccess(fileId, "mallory", "bob")).isInstanceOf(SecurityException.class);
	}

	@Test
	void unrelatedUserHasNoAccess() {
		service.grantAccess(fileId, "alice", "bob", NOW.plusSeconds(60));

		assertThat(service.hasAccess(fileId, "alice", "carol")).isFalse();
	}

	private static final class MutableClock extends Clock {
		private Instant instant;

		private MutableClock(Instant instant) {
			this.instant = instant;
		}

		void setInstant(Instant instant) {
			this.instant = instant;
		}

		@Override
		public ZoneOffset getZone() {
			return ZoneOffset.UTC;
		}

		@Override
		public Clock withZone(java.time.ZoneId zone) {
			return this;
		}

		@Override
		public Instant instant() {
			return instant;
		}
	}
}
