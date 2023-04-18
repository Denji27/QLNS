package net.example.springboot.Service.Impl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import net.example.springboot.DTO.UserDTO;
import net.example.springboot.DTO.MapperDTO;
import net.example.springboot.Model.User;
import net.example.springboot.Model.Permission;
import net.example.springboot.Model.Role;
import net.example.springboot.Repository.*;
import net.example.springboot.Request.*;
import net.example.springboot.Response.AuthenticationResponse;
import net.example.springboot.Service.UserService;
import net.example.springboot.Service.JwtService;
import net.example.springboot.Token.Token;
import net.example.springboot.Token.TokenType;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
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

public class UserServiceImpl implements UserService {
    private UserRepository userRepository;
    private UserRepositoryPageable userRepositoryPageable;
    private RoleRepository roleRepository;
    private PermissionRepository permissionRepository;
    private JwtService jwtService;
    private TokenRepository tokenRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private ModelMapper modelMapper;
    private UserDetailsService userDetailsService;

    @Override
    public User register(RegisterRequest registerRequest) {
        User user = User.builder()
                .name(registerRequest.getName())
                .userName(registerRequest.getUserName())
                .password( passwordEncoder.encode(registerRequest.getPassword()))
                .email(registerRequest.getEmail())
                .DoB(registerRequest.getDoB())
                .status("identifying")
                .role(roleRepository.findRoleByRoleId(3))
                .address(registerRequest.getAddress())
                .build();
        userRepository.save(user);
//        Role role = roleRepository.findRoleByRoleId(3);
//        roleRepository.save(role);
        return user;
    }

    @Override
    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail()
                        , authenticationRequest.getPassword())
        );
        var employee = userRepository.findByEmail(authenticationRequest.getEmail())
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
    private void revokeAllEmployeeTokens(User user) {
        var validEmployeeTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validEmployeeTokens.isEmpty())
            return;
        validEmployeeTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validEmployeeTokens);
    }
    private void saveEmployeeToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    @Override
    public List<UserDTO> showAllEmployee() {
        List<User> users = userRepository.findAll();
        return users.stream()
                .map(e -> modelMapper.map(e, UserDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public void assignRole(AssignRequest assignRequest) {
        for (User user : userRepository.findAll()){
            if(user.getUsername().equals(assignRequest.getEmail())){
                user.setRole(roleRepository.findRoleByRoleId(assignRequest.getRoleId()));
                user.setStatus("approved");
                userRepository.save(user);
            }
        }
    }

    @Override
    public User createAdmin(RegisterRequest registerRequest) {
        User user = User.builder()
                .name(registerRequest.getName())
                .userName(registerRequest.getUserName())
                .password( passwordEncoder.encode(registerRequest.getPassword()))
                .email(registerRequest.getEmail())
                .DoB(registerRequest.getDoB())
                .address(registerRequest.getAddress())
                .role(roleRepository.findRoleByRoleId(1))
                .build();
        User saveUser = userRepository.save(user);
        return user;
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
            var employee = this.userRepository.findByEmail(userEmail)
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
    public UserDTO showProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        MapperDTO mapperDTO = new MapperDTO();
        return mapperDTO.toEmployeeDTO(userRepository.findByEmail(username).get());
    }

    @Override
    public UserDTO changePassword(ChangePasswordRequest request){
        String email = request.getEmail();
        String password = request.getPassword();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();
        UserDetails userDetails= userDetailsService.loadUserByUsername(userEmail);

        if(email.equals(userEmail) && passwordEncoder.matches(password, userDetails.getPassword())){
            Optional<User> employee = userRepository.findByEmail(email);
            User e = employee.get();
            e.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(e);
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
    public List<UserDTO> showAllNoneEmployee() {
        List<User> users = (List<User>) userRepository.findAll();
        List<User> nonUser = new ArrayList<>();
        for (User user : users){
            if (user.getStatus()== null || equals("identifying")){
                nonUser.add(user);
            }
        }
        return nonUser.stream()
                .map(e -> modelMapper.map(e, UserDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public Page<User> showPageAllEmployee(int pageNo, int pageSize) {
        Pageable firstPageWithTwoElements = PageRequest.of(pageNo, pageSize);
        return userRepositoryPageable.findAll(firstPageWithTwoElements);
    }

    @Override
    public void addPermissionToRole(PermissionToRole permissionToRole) {
        Permission permission = permissionRepository.findByPermissionName(permissionToRole.getPermission());
        Role role = roleRepository.findRoleByRoleName(permissionToRole.getRole());
        for(Role r : roleRepository.findAll()){
            if(r.getRoleName().equals(permissionToRole.getRole())){
                Collection<Permission> permissions = r.getPermissions();
                permissions.add(permission);
                r.setPermissions(permissions);
                roleRepository.save(r);
                System.out.println("Success");
            }
        }
    }

}
