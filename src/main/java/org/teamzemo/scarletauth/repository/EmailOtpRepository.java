package org.teamzemo.scarletauth.repository;

import org.teamzemo.scarletauth.entity.EmailOtp;
import org.teamzemo.scarletauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface EmailOtpRepository extends JpaRepository<EmailOtp, UUID> {
    Optional<EmailOtp> findTopByUserAndPurposeOrderByExpiryDateDesc(User user, String purpose);
    void deleteByUser(User user);
}
