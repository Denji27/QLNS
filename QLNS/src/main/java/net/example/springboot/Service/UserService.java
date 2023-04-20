package net.example.springboot.Service;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.example.springboot.DTO.PermissionDTO;
import net.example.springboot.DTO.RoleDTO;
import net.example.springboot.DTO.UserDTO;
import net.example.springboot.Model.User;
import net.example.springboot.Model.Permission;
import net.example.springboot.Model.Role;
import net.example.springboot.Request.*;
import net.example.springboot.Response.AuthenticationResponse;
import org.springframework.data.domain.Page;

import java.io.IOException;
import java.util.List;

public interface UserService {
    User register(RegisterRequest registerRequest);
    AuthenticationResponse login(LoginRequest loginRequest);
    String forgetPassword(ForgetPasswordRequest forgetPasswordRequest) throws MessagingException;



    //admin
    User createAdmin(RegisterRequest registerRequest);
    String assignRole(AssignRequest assignRequest);
    Role createRole(Role role);
    Permission createPermission(Permission permission);
    void addPermissionToRole(PermissionToRole permissionToRole);
    Role removePermission(PermissionToRole permissionToRole);
    List<UserDTO> showAllUsers();
    List<UserDTO> showAllGuestUser();
    Page<User> showPageAllUser(int pageNo, int pageSize);
    String deleteUser(DeleteUserRequest deleteUserRequest);
    List<RoleDTO> showAllRoles();
    List<PermissionDTO> showAllPermission();


    //employee
    String refreshToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException;
    UserDTO showProfile();
    UserDTO changePassword(ChangePasswordRequest request);
}
