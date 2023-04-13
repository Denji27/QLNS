package net.example.springboot.Controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import net.example.springboot.Request.ChangePasswordRequest;
import net.example.springboot.Service.EmployeeService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/v1/employee")
@AllArgsConstructor
public class EmployeeController {
    private EmployeeService employeeService;

    @GetMapping("/profile")
    @PreAuthorize("hasAuthority('2')")
    public ResponseEntity<?> showProfile(){
        return ResponseEntity.ok(employeeService.showProfile());
    }

    @PostMapping("/new-password")
    @PreAuthorize("hasAuthority('2')")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest request){
        return ResponseEntity.ok(employeeService.changePassword(request));
    }
}
