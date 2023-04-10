package net.example.springboot.Repository;

import net.example.springboot.Model.Role;
import net.example.springboot.Token.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    @Query(value = """
      select t from Token t inner join Employee u\s
      on t.employee.id = u.id\s
      where u.id = :id and (t.expired = false or t.revoked = false)\s
      """)
    List<Token> findAllValidTokenByEmployee(long id);

    Optional<Token> findByToken(String token);
}
