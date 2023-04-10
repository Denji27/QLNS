package net.example.springboot.Request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    private String name;
    private String userName;
    private String email;
    private String password;
    private String DoB;
    private String address;
    private long roleId;
}
