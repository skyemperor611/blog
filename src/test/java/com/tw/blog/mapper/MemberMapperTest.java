package com.tw.blog.mapper;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import com.tw.blog.vo.MemberVO;

@WebAppConfiguration
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("file:src/main/webapp/WEB-INF/spring/root-context.xml")
public class MemberMapperTest {
	
	@Autowired
	private MemberMapper memberMapper;
	/*
	@Test
	public void memberJoin() throws Exception{
		MemberVO member = new MemberVO();
		
		member.setUsername("test1");
		member.setPassword("test");
		member.setEmail("test");
		
		memberMapper.memberJoin(member);
	}
	*/
	@Test
	public void usernameChk() throws Exception{
		String id = "admin";
		String id2 = "testtete";
		
		memberMapper.usernameChk(id);
		memberMapper.usernameChk(id2);
	}

}
