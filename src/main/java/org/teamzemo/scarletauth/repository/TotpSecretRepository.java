package org.teamzemo.scarletauth.repository;

import org.teamzemo.scarletauth.entity.TotpSecret;
import org.teamzemo.scarletauth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface TotpSecretRepository extends JpaRepository<TotpSecret, UUID> {
    Optional<TotpSecret> findByUser(User user);
    void deleteByUser(User user);
}
