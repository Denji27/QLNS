package net.example.springboot.Controller;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import net.example.springboot.Request.ChangePasswordRequest;
import net.example.springboot.Service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/employee")
@AllArgsConstructor
@NoArgsConstructor
@PreAuthorize("hasAuthority('EMPLOYEE')")
public class EmployeeController {
    private UserService userService;

    @GetMapping("/profile")
    public ResponseEntity<?> showProfile(){
        return ResponseEntity.ok(userService.showProfile());
    }

    @PostMapping("/new-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request){
        return ResponseEntity.ok(userService.changePassword(request));
    }
}
