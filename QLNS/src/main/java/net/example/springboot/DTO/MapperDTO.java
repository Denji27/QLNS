package net.example.springboot.DTO;

import net.example.springboot.Model.Permission;
import net.example.springboot.Model.User;
import net.example.springboot.Model.Role;

import java.util.ArrayList;
import java.util.Collection;

public class MapperDTO {
    public UserDTO toEmployeeDTO(User user){
        UserDTO userDTO = new UserDTO();
        userDTO.setId(user.getId());
        userDTO.setAddress(user.getAddress());
        userDTO.setEmail(user.getEmail());
        userDTO.setName(user.getName());
        userDTO.setDoB(user.getDoB());
        userDTO.setRole(toRoleDTO(user.getRole()));
        userDTO.setUserName(user.getUsername());
        userDTO.setCreatedDate(user.getCreatedDate());
        userDTO.setLastModifiedDate(user.getLastModifiedDate());
        return userDTO;
    }

    public RoleDTO toRoleDTO(Role role){
        RoleDTO roleDTO = new RoleDTO();
        roleDTO.setId(role.getRoleId());
        roleDTO.setName(role.getRoleName());
        Collection<Permission> permissions = role.getPermissions();
        Collection<PermissionDTO> permissionDTOS = new ArrayList<>();
        for (Permission permission : permissions){
            permissionDTOS.add(toPermissionDTO(permission));
        }
        roleDTO.setPermissions(permissionDTOS);
        return roleDTO;
    }

    public PermissionDTO toPermissionDTO(Permission permission){
        PermissionDTO permissionDTO = new PermissionDTO();
        permissionDTO.setPermissionId(permission.getPermissionId());
        permissionDTO.setPermissionName(permission.getPermissionName());
        permissionDTO.setPermissionDesc(permission.getPermissionDesc());
        return permissionDTO;
    }
}
