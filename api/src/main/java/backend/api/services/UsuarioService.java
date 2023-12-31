package backend.api.services;

import backend.api.DTO.UsuarioDTO;
import backend.api.models.Usuario;
import backend.api.repositories.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.*;

import static org.springframework.http.HttpStatus.*;

@Service
public class UsuarioService {
    @Autowired
    private UsuarioRepository userRepository;

    public ResponseEntity<?> create(Usuario usuario) {
        try {
            if(userRepository.existUsername(usuario.getUsername(), usuario.getEmail()) > 0) {
                return ResponseEntity.status(UNAUTHORIZED).build();
            }

            usuario.setRango(0);
            usuario.setFechaRegistro(new Date());
            userRepository.save(usuario);
        } catch (Exception e) {
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.status(CREATED).body(usuario);
    }

    public ResponseEntity<UsuarioDTO> login(Map<String, String> data){
        try{

            Integer user_id = userRepository.findIdByUsername(data.get("username"));

            if (user_id != null)
            {
                Usuario usuario = userRepository.findById(user_id).orElse(null);

                if(usuario == null || !usuario.getPassword().equals(data.get("password")))
                {
                    return ResponseEntity.status(UNAUTHORIZED).build();
                }
                return ResponseEntity.ok(usuario.toDTO());
            }
            return ResponseEntity.status(UNAUTHORIZED).build();
        } catch (Exception e){
            System.out.println(e);
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
    }

    public ResponseEntity<?> updateProfile(Usuario user){
        try{
            Usuario newUser = userRepository.findById(user.getId()).get();
            newUser.setTelefono(user.getTelefono());
            newUser.setCiudad(user.getCiudad());
            newUser.setDescripcion(user.getDescripcion());
            newUser.setFoto(user.getFoto());
            userRepository.save(newUser);
            return ResponseEntity.status(OK).build();
        } catch (Exception e){
            return ResponseEntity.status(NOT_MODIFIED).build();
        }
    }

    public ResponseEntity<?> updatePassword(Map<String,String> data) {
        try {
            Integer id = Integer.parseInt(data.get("id"));
            Usuario user = userRepository.findById(id).get();
            if (user.getPassword().equals(data.get("oldPassword"))) {
                user.setPassword(data.get("newPassword"));
            }
        } catch (Exception e) {
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.status(OK).build();
    }

    public ResponseEntity<?> deleteUser(Integer id, Usuario u){
        try{
            if (u.getRango() < 3) {
                return ResponseEntity.status(UNAUTHORIZED).build();
            }

            Usuario user = userRepository.findById(id).orElse(null);
            if (user != null) {
                userRepository.delete(user);
                return ResponseEntity.status(OK).build();
            } else {
                return ResponseEntity.status(NOT_FOUND).build();
            }
        } catch (Exception e) {
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
    }

   public List<UsuarioDTO> getAll () {
        try {
            List<UsuarioDTO> usersDTO = new ArrayList<>();
            for (Usuario u : userRepository.findAll()) {
                usersDTO.add(u.toDTO());
            }
            return usersDTO;
        } catch (Exception e) {
            throw new RuntimeException("Error al obtener los usuarios", e);
        }
     }
}
