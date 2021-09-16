package com.tw.blog.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tw.blog.mapper.MemberMapper;
import com.tw.blog.service.MemberService;
import com.tw.blog.vo.MemberVO;

@Service
public class MemberServiceImpl implements MemberService {
	
	@Autowired
	private MemberMapper memmapper;
	
	@Override
	public void memberJoin(MemberVO member) throws Exception {
		memmapper.memberJoin(member);

	}

	@Override
	public MemberVO login(MemberVO userlogin) throws Exception {
		// TODO Auto-generated method stub
		return memmapper.login(userlogin);
	}

	@Override
	public int usernameChk(String username) throws Exception {
		// TODO Auto-generated method stub
		return memmapper.usernameChk(username);
	}

}
