package org.teamzemo.scarletauth.repository;

import org.teamzemo.scarletauth.entity.OAuth2Account;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface OAuth2AccountRepository extends JpaRepository<OAuth2Account, UUID> {
    Optional<OAuth2Account> findByProviderAndProviderUserId(String provider, String providerUserId);
    boolean existsByProviderAndProviderUserId(String provider, String providerUserId);
    boolean existsByUser_Id(UUID userId);
}
