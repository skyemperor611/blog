package com.tw.blog.mapper;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;

import com.tw.blog.vo.BoardVO;

@Mapper
public interface BoardMapper {
	
	public List<BoardVO> getList();
	
	

}
