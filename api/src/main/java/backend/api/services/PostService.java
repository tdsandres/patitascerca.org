package backend.api.services;

import backend.api.DTO.PostDTO;
import backend.api.models.Post;
import backend.api.repositories.PostRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import static org.springframework.http.HttpStatus.*;

@Service
public class PostService {
    @Autowired
    private PostRepository pr;
    @Autowired
    private LikesService likesService;
    @Autowired
    private ComentarioService comentarioService;

    public List<PostDTO> getAll() {
        try {
            List<PostDTO> dto = new ArrayList<>();

            for(Post p: pr.getAllPostsOrdenados()) {
                int idPosteo = p.getId();

                PostDTO post = p.toDTO();

                post.totalComentarios = comentarioService.getCountComentariosByPostId(idPosteo);
                post.totalLikes = likesService.getCountLikesByPostId(idPosteo);
                dto.add(post);
            }
            return dto;
        } catch (Exception e) {
            throw new RuntimeException("Error al obtener los posteos", e);
        }
    }

    public ResponseEntity<?> create(Post p) {
        try {
            p.setFecha(new Date());
            pr.save(p);
        } catch (Exception e) {
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.status(CREATED).build();
    }

    public ResponseEntity<?> updatePost(Post updatedPost) {
        try {
            Post existingPost = pr.findById(updatedPost.getId()).orElse(null);

            assert existingPost != null;

            existingPost.setCategoria(updatedPost.getCategoria());
            existingPost.setDescripcion(updatedPost.getDescripcion());
            existingPost.setUbicacion(updatedPost.getUbicacion());
            existingPost.setImagen(updatedPost.getImagen());

            pr.save(existingPost);

            return ResponseEntity.status(CREATED).build();
        } catch (Exception e) {
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
    }

    public ResponseEntity<?> delete(int postID) {
        try {
            pr.findById(postID).ifPresent(post -> pr.delete(post));
        } catch (Exception e) {
            return ResponseEntity.status(INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.status(CREATED).build();
    }

    public PostDTO getPostById(Integer id) {
        try {
            return Objects.requireNonNull(pr.findById(id).orElse(null)).toDTO();
        } catch (Exception e) {
            throw new RuntimeException("Error al obtener un POST", e);
        }
    }
}
