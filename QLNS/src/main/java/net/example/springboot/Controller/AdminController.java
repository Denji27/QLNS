package net.example.springboot.Controller;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.RegisterRequest;
import net.example.springboot.Service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/admin")
@AllArgsConstructor
@NoArgsConstructor
@PreAuthorize("hasAuthority('ADMIN')")
public class AdminController {
    private UserService userService;

    @GetMapping("/all-employees")
    public ResponseEntity<?> showAllEmployees(){
        return ResponseEntity.ok(userService.showAllEmployee());
    }

    @PostMapping("/new-admin")
    public ResponseEntity<?> createAdmin(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(userService.createAdmin(registerRequest));
    }


    @PostMapping("/role-to-employee")
    public void assignAsUser(@RequestBody AssignRequest assignRequest) {
        userService.assignRole(assignRequest);
    }
}
