package com.tw.blog.mapper;

import org.apache.ibatis.annotations.Mapper;

import com.tw.blog.vo.MemberVO;

@Mapper
public interface MemberMapper {
	
	
	
	public void memberJoin(MemberVO member);
	
	public MemberVO login(MemberVO userlogin);
	
	public int usernameChk(String username);

}
