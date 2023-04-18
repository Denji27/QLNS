package net.example.springboot.Service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
    AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest);
    List<UserDTO> showAllEmployee();
    void assignRole(AssignRequest assignRequest);
    User createAdmin(RegisterRequest registerRequest);
    void refreshToken(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException;
    Role createRole(Role role);
    UserDTO showProfile();
    UserDTO changePassword(ChangePasswordRequest request);
    Permission createPermission(Permission permission);
    List<UserDTO> showAllNoneEmployee();
    Page<User> showPageAllEmployee(int pageNo, int pageSize);
    void addPermissionToRole(PermissionToRole permissionToRole);
    //
}
