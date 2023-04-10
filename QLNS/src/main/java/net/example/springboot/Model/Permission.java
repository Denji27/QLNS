package net.example.springboot.Model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Collection;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "permission")
public class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long permissionId;

    @ManyToMany(mappedBy = "permissions")
    private Collection<Role> roles;

    @Column(name = "permissionName")
    private String permissionName;

    @Column(name = "permissionDesc")
    private String permissionDesc;
}
