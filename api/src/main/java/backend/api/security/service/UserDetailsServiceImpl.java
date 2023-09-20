package backend.api.security.service;

import java.util.List;
import java.util.Set;

import backend.api.repositories.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import backend.api.models.Usuario;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UsuarioRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Integer id = userRepository.findIdByUsername(username);
        Usuario usuario = userRepository.getById(id);

        if (usuario == null) {
            throw new UsernameNotFoundException(username);
        }
        return User
                .withUsername(username)
                .password(usuario.getPassword())
                //.roles(usuario.roles().toArray(new String[0]))
                .build();
    }
}
