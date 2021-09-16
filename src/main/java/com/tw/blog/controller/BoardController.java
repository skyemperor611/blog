package com.tw.blog.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.tw.blog.service.BoardService;
import com.tw.blog.vo.BoardVO;

@Controller
public class BoardController {
	@Autowired
	private BoardService sv;
	private static final Logger logger = LoggerFactory.getLogger(BoardController.class);

	@GetMapping("/main")
	public String list(Model model) {
		
		logger.info("메인페이지 진입");
		List<BoardVO> list = sv.getList();
		
		model.addAttribute("list",list);
		
		return "main";
	}
	
}
