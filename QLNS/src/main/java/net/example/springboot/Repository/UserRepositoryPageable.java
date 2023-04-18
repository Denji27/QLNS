package net.example.springboot.Repository;

import net.example.springboot.Model.User;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface UserRepositoryPageable extends PagingAndSortingRepository<User, Long> {
}
