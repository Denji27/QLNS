package net.example.springboot.Controller;

import lombok.AllArgsConstructor;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.RegisterRequest;
import net.example.springboot.Service.EmployeeService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/admin")
@AllArgsConstructor
public class AdminController {
    private EmployeeService employeeService;

    @GetMapping("/all-employees")
    @PreAuthorize("hasAuthority('1')")
    public ResponseEntity<?> showAllEmployees(){
        return ResponseEntity.ok(employeeService.showAllEmployee());
    }

    @PostMapping("/new-admin")
    @PreAuthorize("hasAuthority('1')")
    public ResponseEntity<?> createAdmin(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(employeeService.createAdmin(registerRequest));
    }

    @PostMapping("/new-role")
    @PreAuthorize("hasAuthority('1')")
    public ResponseEntity<?> createRole(@RequestBody Role role) {
        return ResponseEntity.ok(employeeService.createRole(role));
    }
    @PostMapping("/role-to-employee")
    @PreAuthorize("hasAuthority('1')")
    public void assignAsUser(@RequestBody AssignRequest assignRequest) {
        employeeService.assignRole(assignRequest);
    }
}
