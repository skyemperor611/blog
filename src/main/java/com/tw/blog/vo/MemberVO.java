package com.tw.blog.vo;

public class MemberVO {
	
	/*회원 id*/
	private int userid;
	
	/*회원이름*/
	private String username;
	
	/*비밀번호*/
	private String password;
	
	/*이메일*/
	private String email;
	
	/*생성날짜*/
	private String createDate;
	
	/*업데이트 날짜*/
	private String updateDate;
	
	/*권한*/
	private String role;

	public int getUserid() {
		return userid;
	}

	public void setUserid(int userid) {
		this.userid = userid;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getCreateDate() {
		return createDate;
	}

	public void setCreateDate(String createDate) {
		this.createDate = createDate;
	}

	public String getUpdateDate() {
		return updateDate;
	}

	public void setUpdateDate(String updateDate) {
		this.updateDate = updateDate;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	@Override
	public String toString() {
		return "MemberVO [userid=" + userid + ", username=" + username + ", password=" + password + ", email=" + email
				+ ", createDate=" + createDate + ", updateDate=" + updateDate + ", role=" + role + "]";
	}
	
	

}
