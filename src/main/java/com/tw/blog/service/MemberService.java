package com.tw.blog.service;



import com.tw.blog.vo.MemberVO;


public interface MemberService {
	
	public void memberJoin(MemberVO member) throws Exception;
	
	public MemberVO login(MemberVO userlogin) throws Exception;

	public int usernameChk(String username) throws Exception;

}
