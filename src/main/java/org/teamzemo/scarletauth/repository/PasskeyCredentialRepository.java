package org.teamzemo.scarletauth.repository;

import org.teamzemo.scarletauth.entity.PasskeyCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, UUID> {
    List<PasskeyCredential> findAllByUser_Id(UUID userId);
    List<PasskeyCredential> findAllByUser_Email(String email);
    Optional<PasskeyCredential> findByCredentialId(String credentialId);
    boolean existsByUser_Id(UUID userId);
}
