package net.example.springboot.Service.Impl;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
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
import net.example.springboot.email.EmailService;
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
    private EmailService emailService;

    @Override
    public User register(RegisterRequest registerRequest) {
        User user = User.builder()
                .name(registerRequest.getName())
                .userName(registerRequest.getUserName())
                .password( passwordEncoder.encode(registerRequest.getPassword()))
                .email(registerRequest.getEmail())
                .DoB(registerRequest.getDoB())
                .status("identifying")
                .role(roleRepository.findRoleByRoleId(5))
                .address(registerRequest.getAddress())
                .build();
        userRepository.save(user);
//        Role role = roleRepository.findRoleByRoleId(3);
//        roleRepository.save(role);
        return user;
    }

    @Override
    public AuthenticationResponse login(LoginRequest loginRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail()
                        , loginRequest.getPassword())
        );
        User user = userRepository.findByEmail(loginRequest.getEmail());
        if(user.getRole().getRoleId()!=5) {
            String jwt = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);
            revokeAllEmployeeTokens(user);
            saveEmployeeToken(user, jwt);
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
    public List<UserDTO> showAllUsers() {
        List<User> users = userRepository.findAll();
        return users.stream()
                .map(e -> modelMapper.map(e, UserDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public void assignRole(AssignRequest assignRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();
        User u = userRepository.findByEmail(userEmail);
        if(u.getRole().getPermissions().contains(permissionRepository.findByPermissionName("CREATE"))) {
            for (User user : userRepository.findAll()) {
                if (user.getUsername().equals(assignRequest.getEmail())) {
                    user.setRole(roleRepository.findRoleByRoleId(assignRequest.getRoleId()));
                    user.setStatus("approved");
                    userRepository.save(user);
                }
            }
        }
    }

    @Override
    public User createAdmin(RegisterRequest registerRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();
        User u = userRepository.findByEmail(userEmail);
        if(u.getRole().getPermissions().contains(permissionRepository.findByPermissionName("CREATE"))){
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
        return null;
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
            var employee = this.userRepository.findByEmail(userEmail);
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
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();
        User u = userRepository.findByEmail(userEmail);
        if(u.getRole().getPermissions().contains(permissionRepository.findByPermissionName("CREATE"))){
            return roleRepository.save(role);
        }
        return null;
    }

    @Override
    public UserDTO showProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        MapperDTO mapperDTO = new MapperDTO();
        return mapperDTO.toEmployeeDTO(userRepository.findByEmail(username));
    }

    @Override
    public UserDTO changePassword(ChangePasswordRequest request){
        String email = request.getEmail();
        String password = request.getPassword();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();
        UserDetails userDetails= userDetailsService.loadUserByUsername(userEmail);

        if(email.equals(userEmail) && passwordEncoder.matches(password, userDetails.getPassword())){
            User e = userRepository.findByEmail(email);
            e.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(e);
            MapperDTO mapperDTO = new MapperDTO();

            return mapperDTO.toEmployeeDTO(e);
        }
        return null;
    }

    @Override
    public String forgetPassword(ForgetPasswordRequest forgetPasswordRequest) throws MessagingException {
        String email = forgetPasswordRequest.getEmail();
        List<User> users = userRepository.findAll();
        for (User user : users) {
            if (user.getEmail().equals(email)) {
                user.setPassword(passwordEncoder.encode("newPass"));
                userRepository.save(user);
                emailService.sendMail(email, "Your new password", "newPass");
                return "We have sent an email to give you a new password, please check!!";
            }

        }
        return "We cannot find your email, please fill your email again";
    }

    @Override
    public Permission createPermission(Permission permission) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();
        User u = userRepository.findByEmail(userEmail);
        if(u.getRole().getPermissions().contains(permissionRepository.findByPermissionName("CREATE"))){
            return permissionRepository.save(permission);
        }
        return null;
    }

    @Override
    public List<UserDTO> showAllGuestUser() {
        List<User> users = userRepository.findAll();
        List<User> guest = new ArrayList<>();
        for (User user : users){
            if (user.getStatus().equals("identifying")){
                guest.add(user);
            }
        }
        return guest.stream()
                .map(e -> modelMapper.map(e, UserDTO.class))
                .collect(Collectors.toList());
    }

    @Override
    public Page<User> showPageAllUser(int pageNo, int pageSize) {
        Pageable firstPageWithTwoElements = PageRequest.of(pageNo, pageSize);
        return userRepositoryPageable.findAll(firstPageWithTwoElements);
    }

    @Override
    public String deleteUser(DeleteUserRequest deleteUserRequest) {
        userRepository.delete(userRepository.findByEmail(deleteUserRequest.getEmail()));
        return "Delete " + deleteUserRequest.getEmail() +" user successfully";
    }

    @Override
    public void addPermissionToRole(PermissionToRole permissionToRole) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String userEmail = authentication.getName();
        User u = userRepository.findByEmail(userEmail);
        if(u.getRole().getPermissions().contains(permissionRepository.findByPermissionName("CREATE"))){
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

}
