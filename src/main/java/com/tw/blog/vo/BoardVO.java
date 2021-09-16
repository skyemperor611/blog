package com.tw.blog.vo;

public class BoardVO {
	
	private int boardid;
	
	private String title;
	
	private String content;
	
	private int count;
	
	private String createDate;
	
	private String reupdateDate;
	
	private String username;

	public int getBoardid() {
		return boardid;
	}

	public void setBoardid(int boardid) {
		this.boardid = boardid;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getContent() {
		return content;
	}

	public void setContent(String content) {
		this.content = content;
	}

	public int getCount() {
		return count;
	}

	public void setCount(int count) {
		this.count = count;
	}

	public String getCreateDate() {
		return createDate;
	}

	public void setCreateDate(String createDate) {
		this.createDate = createDate;
	}

	public String getReupdateDate() {
		return reupdateDate;
	}

	public void setReupdateDate(String reupdateDate) {
		this.reupdateDate = reupdateDate;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	@Override
	public String toString() {
		return "BoardVO [boardid=" + boardid + ", title=" + title + ", content=" + content + ", count=" + count
				+ ", createDate=" + createDate + ", reupdateDate=" + reupdateDate + ", username=" + username + "]";
	}

	
	
	

}
