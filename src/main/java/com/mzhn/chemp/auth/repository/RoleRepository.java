package com.mzhn.chemp.auth.repository;

import com.mzhn.chemp.auth.domain.ERole;
import com.mzhn.chemp.auth.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
