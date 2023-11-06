package net.example.springboot.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PermissionDTO {
    private long permissionId;
    private String permissionName;
    private String permissionDesc;
}
