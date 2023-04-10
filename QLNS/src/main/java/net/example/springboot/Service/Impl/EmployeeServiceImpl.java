package net.example.springboot.Service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import net.example.springboot.DTO.EmployeeDTO;
import net.example.springboot.Model.Employee;
import net.example.springboot.Model.Role;
import net.example.springboot.Repository.EmployeeRepository;
import net.example.springboot.Repository.PermissionRepository;
import net.example.springboot.Repository.RoleRepository;
import net.example.springboot.Repository.TokenRepository;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.AuthenticationRequest;
import net.example.springboot.Request.RegisterRequest;
import net.example.springboot.Response.AuthenticationResponse;
import net.example.springboot.Service.EmployeeService;
import net.example.springboot.Service.JwtService;
import net.example.springboot.Token.Token;
import net.example.springboot.Token.TokenType;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class EmployeeServiceImpl implements EmployeeService {
    private EmployeeRepository employeeRepository;
    private RoleRepository roleRepository;
    private JwtService jwtService;
    private TokenRepository tokenRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private ModelMapper modelMapper;

    @Override
    public Employee register(RegisterRequest registerRequest) {
        Employee employee = Employee.builder()
                .name(registerRequest.getName())
                .userName(registerRequest.getUserName())
                .password( passwordEncoder.encode(registerRequest.getPassword()))
                .email(registerRequest.getEmail())
                .DoB(registerRequest.getDoB())
                .role(roleRepository.findRoleByRoleId(3))
                .address(registerRequest.getAddress())
                .build();
        employeeRepository.save(employee);
        Role role = roleRepository.findRoleByRoleId(3);
        roleRepository.save(role);
        return employee;
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail()
                        , authenticationRequest.getPassword())
        );
        var employee = employeeRepository.findByEmail(authenticationRequest.getEmail())
                .orElseThrow();
        String jwt = jwtService.generateToken(employee);
        String refreshToken = jwtService.generateRefreshToken(employee);
        revokeAllEmployeeTokens(employee);
        saveEmployeeToken(employee, jwt);
        return AuthenticationResponse.builder()
                .jwt(jwt)
                .refreshToken(refreshToken)
                .build();
    }
    private void revokeAllEmployeeTokens(Employee employee) {
        var validEmployeeTokens = tokenRepository.findAllValidTokenByEmployee(employee.getId());
        if (validEmployeeTokens.isEmpty())
            return;
        validEmployeeTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validEmployeeTokens);
    }
    private void saveEmployeeToken(Employee employee, String jwtToken) {
        var token = Token.builder()
                .employee(employee)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    @Override
    public List<EmployeeDTO> showAllEmployee() {
        List<Employee> employees = employeeRepository.findAll();
        return employees.stream()
                .map(e -> modelMapper.map(e, EmployeeDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public void assignRole(AssignRequest assignRequest) {
        for (Employee employee : employeeRepository.findAll()){
            if(employee.getUsername().equals(assignRequest.getEmail())){
                employee.setRole(roleRepository.findRoleByRoleId(assignRequest.getRoleId()));
                employeeRepository.save(employee);
            }
        }
    }

    @Override
    public Employee createAdmin(RegisterRequest registerRequest) {
        Employee employee= Employee.builder()
                .name(registerRequest.getName())
                .userName(registerRequest.getUserName())
                .password( passwordEncoder.encode(registerRequest.getPassword()))
                .email(registerRequest.getEmail())
                .DoB(registerRequest.getDoB())
                .address(registerRequest.getAddress())
                .role(roleRepository.findRoleByRoleId(1))
                .build();
        Employee saveEmployee = employeeRepository.save(employee);
        return employee;
    }

    @Override
    public void refreshToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
         String authHeader = httpServletRequest.getHeader("Authorization");
         String refreshToken;
        String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            return;
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtService.extractEmail(refreshToken);
        if (userEmail != null){
            var employee = this.employeeRepository.findByEmail(userEmail)
                    .orElseThrow();
            if(jwtService.isTokenValid(refreshToken, employee)){
                String accessToken = jwtService.generateToken(employee);
                saveEmployeeToken(employee, accessToken);
                AuthenticationResponse authenticationResponse = AuthenticationResponse.builder()
                        .jwt(accessToken)
                        .refreshToken(refreshToken)
                        .build();
            }
        }
    }

    @Override
    public Role createRole(Role role) {
        return roleRepository.save(role);
    }
}
