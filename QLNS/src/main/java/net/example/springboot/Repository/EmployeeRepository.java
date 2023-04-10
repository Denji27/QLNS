package net.example.springboot.Repository;

import net.example.springboot.Model.Employee;
import net.example.springboot.Model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Collection;
import java.util.Optional;

public interface EmployeeRepository extends JpaRepository<Employee, Long> {
    public Optional<Employee> findByEmail(String email);
    public Collection<Employee> findAllByRole(Role role);
}
