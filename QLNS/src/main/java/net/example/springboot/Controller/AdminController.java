package net.example.springboot.Controller;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import net.example.springboot.Model.Permission;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.DeleteUserRequest;
import net.example.springboot.Request.PermissionToRole;
import net.example.springboot.Request.RegisterRequest;
import net.example.springboot.Service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/admin")
@AllArgsConstructor
//@PreAuthorize("hasAuthority('ADMIN')")
public class AdminController {
    private UserService userService;

    @PostMapping("/new-admin")
    public ResponseEntity<?> createAdmin(@RequestBody RegisterRequest registerRequest) {
        return ResponseEntity.ok(userService.createAdmin(registerRequest));
    }

    @PostMapping("/role-to-user")
    public void assignAsUser(@RequestBody AssignRequest assignRequest) {
        userService.assignRole(assignRequest);
    }

    @GetMapping("/guests")
    public ResponseEntity<?> showAllGuests(){
        return ResponseEntity.ok(userService.showAllGuestUser());
    }

    @GetMapping("/users")
    public ResponseEntity<?> showPageAllUsers(@RequestParam(defaultValue = "0") Integer pageNo,
                                                  @RequestParam(defaultValue = "2") Integer pageSize){
        return ResponseEntity.ok(userService.showPageAllUser(pageNo, pageSize));
    }
    @GetMapping("/all-users")
    public ResponseEntity<?> showAllUsers(){
        return ResponseEntity.ok(userService.showAllUsers());
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

    @DeleteMapping("/user")
    public ResponseEntity<?> deleteUser(@RequestBody DeleteUserRequest deleteUserRequest){
        return ResponseEntity.ok(userService.deleteUser(deleteUserRequest));
    }
}
