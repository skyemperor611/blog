package com.blog.my.service;

import com.blog.my.domain.Article;
import com.blog.my.dto.AddArticleRequest;
import com.blog.my.dto.UpdateArticleRequest;
import com.blog.my.repository.BlogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@RequiredArgsConstructor
@Service
public class BlogService {

    private final BlogRepository blogRepository;

    public Article save(AddArticleRequest request, String userName){
        return blogRepository.save(request.toEntity(userName));
    }
    public List<Article> findAll() {
        return blogRepository.findAll();
    }
    public Article findByID(long id) {
        return blogRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("not found : " + id));
    }
    public void delete(long id) {
        blogRepository.deleteById(id);
    }

    @Transactional
    public Article update(long id, UpdateArticleRequest request) {
        Article article = blogRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("not found : " + id));

        article.update(request.getTitle(), request.getContent());

        return article;
    }

}
