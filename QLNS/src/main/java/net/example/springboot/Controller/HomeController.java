package net.example.springboot.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.AuthenticationRequest;
import net.example.springboot.Request.RegisterRequest;
import net.example.springboot.Service.EmployeeService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/home")
@AllArgsConstructor
public class HomeController {
    private EmployeeService employeeService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(employeeService.register(registerRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest authenticationRequest) {
        return ResponseEntity.ok(employeeService.authenticate(authenticationRequest));
    }

    @PostMapping("/create-admin")
    public ResponseEntity<?> createAdmin(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(employeeService.createAdmin(registerRequest));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        employeeService.refreshToken(request, response);
    }

    @PostMapping("/create-role")
    public ResponseEntity<?> createRole(@RequestBody Role role) {
        return ResponseEntity.ok(employeeService.createRole(role));
    }

    @PostMapping("/assign-as-user")
    public void assignAsUser(@RequestBody AssignRequest assignRequest) {
        employeeService.assignRole(assignRequest);
    }

    @GetMapping("/all-employees")
    public ResponseEntity<?> showAllEmployees(){
        return ResponseEntity.ok(employeeService.showAllEmployee());
    }
}
