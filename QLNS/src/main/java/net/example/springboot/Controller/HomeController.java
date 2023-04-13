package net.example.springboot.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import net.example.springboot.Model.Permission;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.AuthenticationRequest;
import net.example.springboot.Request.RegisterRequest;
import net.example.springboot.Service.EmployeeService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/v1/home")
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

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        employeeService.refreshToken(request, response);
    }

    @GetMapping("/all-employees")
    public ResponseEntity<?> showAllEmployees(){
        return ResponseEntity.ok(employeeService.showAllEmployee());
    }

    @PostMapping("/permission")
    public ResponseEntity<?> createPermission(@RequestBody Permission permission){
        return ResponseEntity.ok(employeeService.createPermission(permission));
    }
//    @PostMapping("/permission")
//    public ResponseEntity<?> addRoleToPermission(@RequestBody String permissionName){
//        return ResponseEntity.ok(employeeService.addRoleToPermission(permissionName));
//    }

    @PostMapping("/role-to-employee")
    public void assignAsUser(@RequestBody AssignRequest assignRequest) {
        employeeService.assignRole(assignRequest);
    }

    @GetMapping("/none-employee")
    public ResponseEntity<?> showAllNoneEmployee(){
        return ResponseEntity.ok(employeeService.showAllNoneEmployee());
    }

    @GetMapping("/employees")
    public ResponseEntity<?> showPageAllEmployees(@RequestParam(defaultValue = "0") Integer pageNo,
                                                  @RequestParam(defaultValue = "2") Integer pageSize){
        return ResponseEntity.ok(employeeService.showPageAllEmployee(pageNo, pageSize));
    }
}
