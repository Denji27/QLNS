package net.example.springboot.Service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.example.springboot.DTO.EmployeeDTO;
import net.example.springboot.Model.Employee;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.AuthenticationRequest;
import net.example.springboot.Request.RegisterRequest;
import net.example.springboot.Response.AuthenticationResponse;

import java.io.IOException;
import java.util.List;

public interface EmployeeService {
    public Employee register(RegisterRequest registerRequest);
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest);
    public List<EmployeeDTO> showAllEmployee();
    public void assignRole(AssignRequest assignRequest);
    public Employee createAdmin(RegisterRequest registerRequest);
    public void refreshToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException;
    public Role createRole(Role role);
}
