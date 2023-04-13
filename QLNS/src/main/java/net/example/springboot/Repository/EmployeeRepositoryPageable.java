package net.example.springboot.Repository;

import net.example.springboot.Model.Employee;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface EmployeeRepositoryPageable extends PagingAndSortingRepository<Employee, Long> {
}
