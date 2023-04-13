package net.example.springboot.Service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import net.example.springboot.DTO.EmployeeDTO;
import net.example.springboot.DTO.MapperDTO;
import net.example.springboot.Model.Employee;
import net.example.springboot.Model.Permission;
import net.example.springboot.Model.Role;
import net.example.springboot.Repository.*;
import net.example.springboot.Request.AssignRequest;
import net.example.springboot.Request.AuthenticationRequest;
import net.example.springboot.Request.ChangePasswordRequest;
import net.example.springboot.Request.RegisterRequest;
import net.example.springboot.Response.AuthenticationResponse;
import net.example.springboot.Service.EmployeeService;
import net.example.springboot.Service.JwtService;
import net.example.springboot.Token.Token;
import net.example.springboot.Token.TokenType;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class EmployeeServiceImpl implements EmployeeService {
    private EmployeeRepository employeeRepository;
    private EmployeeRepositoryPageable employeeRepositoryPageable;
    private RoleRepository roleRepository;
    private PermissionRepository permissionRepository;
    private JwtService jwtService;
    private TokenRepository tokenRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private ModelMapper modelMapper;
    private UserDetailsService userDetailsService;

    @Override
    public Employee register(RegisterRequest registerRequest) {
        Employee employee = Employee.builder()
                .name(registerRequest.getName())
                .userName(registerRequest.getUserName())
                .password( passwordEncoder.encode(registerRequest.getPassword()))
                .email(registerRequest.getEmail())
                .DoB(registerRequest.getDoB())
                .status("identifying")
                .role(roleRepository.findRoleByRoleId(3))
                .address(registerRequest.getAddress())
                .build();
        employeeRepository.save(employee);
//        Role role = roleRepository.findRoleByRoleId(3);
//        roleRepository.save(role);
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
        if(employee.getRole().getRoleId()!=3) {
            String jwt = jwtService.generateToken(employee);
            String refreshToken = jwtService.generateRefreshToken(employee);
            revokeAllEmployeeTokens(employee);
            saveEmployeeToken(employee, jwt);
            return AuthenticationResponse.builder()
                    .jwt(jwt)
                    .refreshToken(refreshToken)
                    .build();
        }
        return AuthenticationResponse.builder()
                .jwt("Your account hasn't been approved yet")
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
                employee.setStatus("approved");
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

    @Override
    public EmployeeDTO showProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        MapperDTO mapperDTO = new MapperDTO();
        return mapperDTO.toEmployeeDTO(employeeRepository.findByEmail(username).get());
    }

    @Override
    public EmployeeDTO changePassword(ChangePasswordRequest request){
        String email = request.getEmail();
        String password = request.getPassword();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();
        UserDetails userDetails= userDetailsService.loadUserByUsername(userEmail);

        if(email.equals(userEmail) && passwordEncoder.matches(password, userDetails.getPassword())){
            Optional<Employee> employee = employeeRepository.findByEmail(email);
            Employee e = employee.get();
            e.setPassword(passwordEncoder.encode(request.getNewPassword()));
            employeeRepository.save(e);
            MapperDTO mapperDTO = new MapperDTO();

            return mapperDTO.toEmployeeDTO(e);
        }
        return null;
    }

    @Override
    public Permission createPermission(Permission permission) {
        return permissionRepository.save(permission);
    }

    @Override
    public List<EmployeeDTO> showAllNoneEmployee() {
        List<Employee> employees = (List<Employee>) employeeRepository.findAll();
        List<Employee> nonEmployee= new ArrayList<>();
        for (Employee employee : employees){
            if (employee.getStatus()== null || equals("identifying")){
                nonEmployee.add(employee);
            }
        }
        return nonEmployee.stream()
                .map(e -> modelMapper.map(e, EmployeeDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public Page<Employee> showPageAllEmployee(int pageNo, int pageSize) {
        Pageable firstPageWithTwoElements = PageRequest.of(pageNo, pageSize);
        return employeeRepositoryPageable.findAll(firstPageWithTwoElements);
    }

}
