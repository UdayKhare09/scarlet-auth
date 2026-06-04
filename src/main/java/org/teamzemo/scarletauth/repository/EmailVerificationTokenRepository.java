package org.teamzemo.scarletauth.repository;

import org.teamzemo.scarletauth.entity.EmailVerificationToken;
import org.teamzemo.scarletauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, UUID> {
    Optional<EmailVerificationToken> findByToken(String token);
    Optional<EmailVerificationToken> findByUser(User user);
    void deleteByUser(User user);
}
