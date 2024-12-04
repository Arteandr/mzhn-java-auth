package com.mzhn.chemp.auth.repository;

import com.mzhn.chemp.auth.domain.User;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    boolean existsByEmail(String email);

    Optional<User> findOneByEmail(@NotBlank String email);

    Optional<User> findOneById(UUID id);
}