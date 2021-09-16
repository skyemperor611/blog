package com.tw.blog.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tw.blog.service.MemberService;
import com.tw.blog.vo.MemberVO;

@Controller
public class MemberController {
	
	private static final Logger logger = LoggerFactory.getLogger(MemberController.class);
	
	@Autowired
	private MemberService memservice;
	
	@GetMapping("/join")
	public void joinGET() {
		logger.info("회원가입 페이지 진입");
	}
	
	@PostMapping("/join")
	public String joinPOST(MemberVO member) throws Exception{
		
		logger.info("join 진입");
		
		memservice.memberJoin(member);
		
		logger.info("join service 성공");
		
		return "redirect:/login";
	}
	
	@PostMapping("/usernameChk")
	@ResponseBody
	public String usernameChk(String userName) throws Exception{
		logger.info("userName() 진입");
		
		int result = memservice.usernameChk(userName);
		
		logger.info("결과값" + result);
		
		if(result != 0) {
			return "fail";
		} else {
			return "success";
		}
	}
	
	@GetMapping("/login")
	public void loginGET() {
		logger.info("로그인 페이지 진입");
	}
	
	@PostMapping("/login")
	public String login(MemberVO memLogin, HttpServletRequest req, RedirectAttributes rttr) throws Exception{
		
		logger.info("로그인 시작");
		
		HttpSession session = req.getSession();
		MemberVO login = memservice.login(memLogin);
		
		if(login == null) {
			int result = 0;
			rttr.addFlashAttribute("result",result);
			logger.info("로그인 실패");
			return "redirect:/login";
		} else {
			session.setAttribute("member", login);
			logger.info("로그인 성공");
		}
		
		return "redirect:/main";
		
	}
	
	@GetMapping("/logout")
	public String logout(HttpSession session) throws Exception{
		session.invalidate();
		
		return "redirect:/";
	}
	

}
