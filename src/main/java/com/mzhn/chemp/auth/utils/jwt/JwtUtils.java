package com.mzhn.chemp.auth.utils.jwt;

import com.mzhn.chemp.auth.domain.ERole;
import com.mzhn.chemp.auth.domain.Role;
import com.mzhn.chemp.auth.dto.auth.TokensResponse;
import com.mzhn.chemp.auth.dto.auth.UserClaims;
import io.jsonwebtoken.Claims;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwtUtils {

    public static UserClaims generate(Claims claims) {
        final UserClaims userClaims = new UserClaims();
        userClaims.setRoles(getRoles(claims));
        userClaims.setId(UUID.fromString(claims.get("id", String.class)));
        userClaims.setEmail(claims.getSubject());
        return userClaims;
    }

    private static Set<Role> getRoles(Claims claims) {
        List<Object> rolesList = (List<Object>) claims.get("roles");
        Set<Role> roles = (Set<Role>) rolesList.stream()
                .map(roleObj -> {
                    var roleMap = (Map<String, Object>) roleObj;
                    int id = (int) roleMap.get("id");
                    String name = (String) roleMap.get("name");
                    return new Role(id, ERole.valueOf(name));
                }).collect(Collectors.toSet());
        return roles;
    }

}