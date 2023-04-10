package net.example.springboot.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class EmployeeDTO {
    private long id;
    private String name;
    private String userName;
    private String password;
    private String email;
    private RoleDTO role;
    private String DoB;
    private String address;

    private String status;
    private LocalDateTime createdDate;
    private LocalDateTime lastModifiedDate;
}
