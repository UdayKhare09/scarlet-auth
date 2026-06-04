package org.teamzemo.scarletauth.repository;

import org.teamzemo.scarletauth.entity.MfaSettings;
import org.teamzemo.scarletauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface MfaSettingsRepository extends JpaRepository<MfaSettings, UUID> {
    Optional<MfaSettings> findByUser(User user);
}
