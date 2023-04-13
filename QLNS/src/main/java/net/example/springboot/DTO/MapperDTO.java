package net.example.springboot.DTO;

import net.example.springboot.Model.Employee;
import net.example.springboot.Model.Role;

public class MapperDTO {
    public EmployeeDTO toEmployeeDTO(Employee employee){
        EmployeeDTO employeeDTO= new EmployeeDTO();
        employeeDTO.setId(employee.getId());
        employeeDTO.setAddress(employee.getAddress());
        employeeDTO.setEmail(employee.getEmail());
        employeeDTO.setName(employee.getName());
        employeeDTO.setDoB(employee.getDoB());
        employeeDTO.setRole(toRoleDTO(employee.getRole()));
        employeeDTO.setUserName(employee.getUsername());
        employeeDTO.setCreatedDate(employee.getCreatedDate());
        employeeDTO.setLastModifiedDate(employee.getLastModifiedDate());
        return employeeDTO;
    }

    public RoleDTO toRoleDTO(Role role){
        RoleDTO roleDTO = new RoleDTO();
        roleDTO.setId(role.getRoleId());
        roleDTO.setRoleName(role.getRoleName());
        return roleDTO;
    }
}
