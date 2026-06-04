package org.teamzemo.scarletauth.repository;

import org.teamzemo.scarletauth.entity.User;
import org.teamzemo.scarletauth.entity.UserPassword;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserPasswordRepository extends JpaRepository<UserPassword, UUID> {
    Optional<UserPassword> findByUser_Id(UUID userId);
    Optional<UserPassword> findByUser_Email(String email);
    boolean existsByUser_Id(UUID userId);
    Optional<UserPassword> findByUser(User user);
}
