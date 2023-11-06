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
@Table(name = "Roles")
public class Role extends Auditable{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long roleId;

//    @OneToMany(mappedBy = "role", cascade = CascadeType.ALL)
//    private Collection<Employee> employees;

    @ManyToMany(fetch=FetchType.EAGER)
    @JoinTable(
            name = "role_has_permission",
            joinColumns = @JoinColumn(name = "roleId"),
            inverseJoinColumns = @JoinColumn(name = "permissionId"))
    private Collection<Permission> permissions;

    @Column(name = "roleName")
    private String roleName;
}
