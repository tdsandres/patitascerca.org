package backend.api.services;

import backend.api.DTO.UsuarioDTO;
import backend.api.models.Usuario;
import backend.api.repositories.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;


import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.springframework.http.HttpStatus.*;

@Service
public class UsuarioService {

    @Autowired
    private UsuarioRepository userRepository;

    public ResponseEntity create(Usuario usuario) {
        try {
            usuario.setRango(0);
            usuario.setFechaRegistro(new Date());
            userRepository.save(usuario);
        } catch (Exception e) {
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.status(CREATED).build();
    }

    public ResponseEntity<Usuario> login(String username, String password){
        try{
            Integer user_id = userRepository.findIdByUsername(username);
            Usuario usuario = userRepository.findById(user_id).orElse(null);
            if(usuario == null || !usuario.getPassword().equals(password)){
                return ResponseEntity.status(UNAUTHORIZED).build();
            }
            return ResponseEntity.ok(usuario);
        } catch (Exception e){
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
    }


    public List<UsuarioDTO> getAll() {
        List<UsuarioDTO> usersDTO = new ArrayList<>();

        for(Usuario u : userRepository.findAll()) {
            usersDTO.add(u.toDTO());
        }

        return usersDTO;
    }

}
