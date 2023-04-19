package net.example.springboot.Controller;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import net.example.springboot.Model.Permission;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.*;
import net.example.springboot.Service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/v1/home")
@AllArgsConstructor
@Data
public class HomeController {
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(userService.register(registerRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(userService.login(loginRequest));
    }

    @PostMapping("/forget-password")
    public ResponseEntity<?> forgetPassword(@RequestBody ForgetPasswordRequest forgetPasswordRequest) throws MessagingException {
        return ResponseEntity.ok(userService.forgetPassword(forgetPasswordRequest));
    }
//    @PostMapping("/admin")
//    public ResponseEntity<?> createAdmin(@RequestBody RegisterRequest registerRequest) {
//        return ResponseEntity.ok(userService.createAdmin(registerRequest));
//    }
//    @PostMapping("/permission-to-role")
//    public String addPermissionToRole(@RequestBody PermissionToRole permissionToRole){
//        userService.addPermissionToRole(permissionToRole);
//        return "add successfully";
//    }
//    @PostMapping("/new-role")
//    public ResponseEntity<?> createRole(@RequestBody Role role) {
//        return ResponseEntity.ok(userService.createRole(role));
//    }
//    @PostMapping("/permission")
//    public ResponseEntity<?> createPermission(@RequestBody Permission permission){
//        return ResponseEntity.ok(userService.createPermission(permission));
//    }
}
