package com.blog.my.controller;

import com.blog.my.dto.AddUserRequests;
import com.blog.my.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

@RequiredArgsConstructor
@Controller
public class UserApiController {

    private final UserService userService;

    @PostMapping("/user")
    public String signup(AddUserRequests request) {
        userService.save(request);
        return "redirect:/login";
    }
}
