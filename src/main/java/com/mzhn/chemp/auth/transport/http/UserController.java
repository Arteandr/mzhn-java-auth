package com.mzhn.chemp.auth.transport.http;

import com.mzhn.chemp.auth.domain.User;
import com.mzhn.chemp.auth.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@AllArgsConstructor
@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService userService;

    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok().body(userService.getAllUsers());
    }

    @PostMapping
    public ResponseEntity<User> saveEmployee(@RequestBody User user)
    {
        return ResponseEntity.ok().body(userService.saveUser(user));
    }
}
