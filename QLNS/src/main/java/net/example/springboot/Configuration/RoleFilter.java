//package net.example.springboot.Configuration;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import net.example.springboot.Model.User;
//import net.example.springboot.Repository.UserRepository;
//import net.example.springboot.Service.JwtService;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//import java.util.Optional;
//
//@Component
//@RequiredArgsConstructor
//public class RoleFilter extends OncePerRequestFilter {
//    private final UserRepository userRepository;
//    private final JwtService jwtService;
//    @Override
//    protected void doFilterInternal(HttpServletRequest request,
//                                    HttpServletResponse response,
//                                    FilterChain filterChain) throws ServletException, IOException {
//        String authHeader = request.getHeader("Authorization");
//        String jwt;
//        String email;
//        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//        jwt= authHeader.substring(7);
//        email = jwtService.extractEmail(jwt);
//        Optional<User> employee = userRepository.findByEmail(email);
//        String role = employee.get().getRole().getRoleName();
//        if(!(role.equals("ADMIN") || equals("EMPLOYEE"))){
//            filterChain.doFilter(request, response);
//            return;
//        }
//        filterChain.doFilter(request, response);
//    }
//}
