package org.teamzemo.scarletauth.repository;

import org.teamzemo.scarletauth.entity.PendingMfaToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PendingMfaTokenRepository extends JpaRepository<PendingMfaToken, UUID> {
    Optional<PendingMfaToken> findByToken(String token);
    void deleteByToken(String token);
}
