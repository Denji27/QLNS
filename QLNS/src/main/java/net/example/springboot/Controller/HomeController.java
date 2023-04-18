package net.example.springboot.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import net.example.springboot.Model.Permission;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.AuthenticationRequest;
import net.example.springboot.Request.PermissionToRole;
import net.example.springboot.Request.RegisterRequest;
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
    public ResponseEntity<?> login(@RequestBody AuthenticationRequest authenticationRequest) {
        return ResponseEntity.ok(userService.authenticate(authenticationRequest));
    }

    @PostMapping("/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        userService.refreshToken(request, response);
    }

    @GetMapping("/all-employees")
    public ResponseEntity<?> showAllEmployees(){
        return ResponseEntity.ok(userService.showAllEmployee());
    }

    @PostMapping("/permission")
    public ResponseEntity<?> createPermission(@RequestBody Permission permission){
        return ResponseEntity.ok(userService.createPermission(permission));
    }

    @PostMapping("/new-role")
    public ResponseEntity<?> createRole(@RequestBody Role role) {
        return ResponseEntity.ok(userService.createRole(role));
    }

    @PostMapping("/permission-to-role")
    public String addPermissionToRole(@RequestBody PermissionToRole permissionToRole){
        userService.addPermissionToRole(permissionToRole);
        return "add successfully";
    }

//    @PostMapping("/permission")
//    public ResponseEntity<?> addRoleToPermission(@RequestBody String permissionName){
//        return ResponseEntity.ok(employeeService.addRoleToPermission(permissionName));
//    }

    @PostMapping("/role-to-employee")
    public void assignAsUser(@RequestBody AssignRequest assignRequest) {
        userService.assignRole(assignRequest);
    }

    @GetMapping("/guests")
    public ResponseEntity<?> showAllNoneEmployee(){
        return ResponseEntity.ok(userService.showAllNoneEmployee());
    }

    @GetMapping("/employees")
    public ResponseEntity<?> showPageAllEmployees(@RequestParam(defaultValue = "0") Integer pageNo,
                                                  @RequestParam(defaultValue = "2") Integer pageSize){
        return ResponseEntity.ok(userService.showPageAllEmployee(pageNo, pageSize));
    }
}
