<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<c:set var="path" value="${pageContext.request.contextPath}"></c:set>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Bootstrap 101 Template</title>
<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
   <link href="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"></script>
<link href="${path}/resources/css/join.css" rel="stylesheet" type="text/css">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.0.8/css/all.css">
<link rel="stylesheet" type="text/css" href="${path}/resources/bootstrap-social-gh-pages/bootstrap-social.css">
<link rel="stylesheet" type="text/css" href="${path}/resources/bootstrap-social-gh-pages/assets/css/font-awesome.css">
<style type="text/css">
.username_ck{

display: none;
color: red;
position: absolute;
top: 35px;
font-size: small;  
  }

.email_ck{

display: none;
  color: red;
position: absolute;
top: 35px;
font-size: small;  
  }
  
.password_ck{

display: none;
  color: red;
position: absolute;
top: 35px;
font-size: small;  
  }
  

.join_button{
 
}

.username_input_re1{
	color: green;
	display: none;
	position: absolute;
	top: 35px;
font-size: small; 
}
.username_input_re2{
	color: red;
	display: none;
	position: absolute;
	top: 35px;
font-size: small; 
}                      
</style>

<script>
var userNameCheck = false;
var userNameckCheck = false;
var pwCheck = false;
var pwckCheck = false;
var emailCheck = false;
var emailckCheck = false;

$(document).ready(function(){
	$('.join_button').click(function(){
		
		var userName = $('.input_username').val();
		var email = $('.input_email').val();
		var pw = $('.input_password').val();
		
		if(userName == ""){
			
			$('.username_ck').css('display','block');
			userNameCheck = false;
			
		} else {
			$('.username_ck').css('display','none');
			userNameCheck = true;
		}
		
	if(email == ""){
			
			$('.email_ck').css('display','block');
			userNameCheck = false;
			
		} else {
			$('.email_ck').css('display','none');
			userNameCheck = true;
		}
	
	if(pw == ""){
		
		$('.password_ck').css('display','block');
		userNameCheck = false;
		
	} else {
		$('.password_ck').css('display','none');
		userNameCheck = true;
	}
	});
	
	/* 사용자명 중복 검사*/
	 $('.input_username').on("propertychange change keyup paste input", function(){
		 
		
		 var userName = $('.input_username').val();
		 var data = {userName : userName}
		
		 
		 $.ajax({
			 type: "post",
			 url: "/usernameChk",
			 data: data,
			 success : function(result){
				 console.log('성공여부' + result);
				 if(result != 'fail') {
					 $('.username_input_re1').css("display","inline-block");
					 $('.username_input_re2').css("display","none");
				 } else {
					 $('.username_input_re2').css("display","inline-block");
					 $('.username_input_re1').css("display","none");
				 }
			 }
		 });
	 });	
	/* 입력 이메일 형식 유효성 검사*/
	
	
	
	 $(".input_email").keyup(function(){
			
			var email = $(".input_email").val();
			var warnMsg = $(".mail_input_box_warn");
		
			if(email != 0){
				if(isValidEmailAddress(email)){
					warnMsg.html("유효한 이메일 형식입니다.");
					warnMsg.css("display", "inline-block");
					warnMsg.css("position", "absolute");
					warnMsg.css("color", "green");
					warnMsg.css("top", "35px");
					warnMsg.css("font-size", "small");
					
				} else {
					warnMsg.html("유효하지 않은 이메일 형식입니다.");
					warnMsg.css("display", "inline-block");
					warnMsg.css("position", "absolute");
					warnMsg.css("color", "red");
					warnMsg.css("top", "35px");
					warnMsg.css("font-size", "small");
				}
			} else {
				warnMsg.html("이메일 주소를 입력해주세요.");
				warnMsg.css("display", "inline-block");
				warnMsg.css("position", "absolute");
				warnMsg.css("color", "blue");
				warnMsg.css("top", "35px");
				warnMsg.css("font-size", "small");
			}
		
		});
	
	 function isValidEmailAddress(emailAddress) {
			var pattern = new RegExp(/^(("[\w-\s]+")|([\w-]+(?:\.[\w-]+)*)|("[\w-\s]+")([\w-]+(?:\.[\w-]+)*))(@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$)|(@\[?((25[0-5]\.|2[0-4][0-9]\.|1[0-9]{2}\.|[0-9]{1,2}\.))((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){2}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\]?$)/i);
			return pattern.test(emailAddress);
		}
});



 

/* 사용자명 유효성 검사 */



</script>

  </head>
  
 
  <body>
  
 





<div class="card bg-light">
<article class="card-body mx-auto" style="max-width: 400px;">
	<h4 class="card-title mt-3 text-center">Create Account</h4>
	<p class="text-center">Get started with your free account</p>
	<p>
		<a href="" class="btn btn-block btn-social btn-kakao"> <i class="fa fa-kakao"></i>   Login via Kakao</a>
		<a href="" class="btn btn-block btn-social btn-facebook"> <i class="fa fa-facebook"></i>   Login via facebook</a>
		<a href="" class="btn btn-block btn-social btn-google"> <i class="fa fa-google"></i>   Login via Google</a>
 
	</p>
	<p class="divider-text">
        <span class="bg-light">OR</span>
    </p>
	<form>
	<div class="form-group input-group">
		<div class="input-group-prepend">
		    <span class="input-group-text"> <i class="fa fa-user"></i> </span>
		 </div>
        <input id="input_username" name="username" class="form-control input_username" placeholder="Full name" type="text">
        <span class="username_input_re1">사용 가능한 사용자명 입니다.</span>
          <span class="username_input_re2">사용자명이 이미 존재 합니다.</span>
          <span class="username_ck">사용자명을 입력해주세요.</span>
        
    </div> <!-- form-group// -->
    <div class="form-group input-group">
    	<div class="input-group-prepend">
		    <span class="input-group-text"> <i class="fa fa-envelope"></i> </span>
		 </div>
        <input id="input_email" name="email" class="form-control input_email" placeholder="Email address" type="email">
           <span class="email_ck">이메일을 입력해주세요.</span>
           <span class="mail_input_box_warn"></span>
    </div> 
  
    <!-- form-group// -->
    
    
    <div class="form-group input-group">
    	<div class="input-group-prepend">
		    <span class="input-group-text"> <i class="fa fa-lock"></i> </span>
		</div>
        <input id="input_password" class="form-control input_password" placeholder="Create password" type="password" name="password">
   <span class="password_ck">비밀번호를 입력해주세요.</span>
    </div> 
     
    <!-- form-group// -->
                                  
    <div class="form-group join_button">
        
        <input id="join_button" type="button" class="btn btn-primary btn-block" value="가입하기">
    </div> <!-- form-group// -->      
    <p class="text-center">Have an account? <a href="/login">Log In</a> </p>                                                                 
</form>
</article>
</div> <!-- card.// -->


<!--container end.//-->

<br><br>

  </body>
</html>