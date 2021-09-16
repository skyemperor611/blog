<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%> 
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>   
<c:set var="path" value="${pageContext.request.contextPath}"></c:set>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
 <link href="//netdna.bootstrapcdn.com/bootstrap/3.1.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
 <link href="${path}/resources/css/login.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="${path}/resources/js/jquery.min.js"></script>
<script
  src="https://code.jquery.com/jquery-3.6.0.js"
  integrity="sha256-H+K7U5CnXl1h5ywQfKtSj8PCmoN9aaq30gDh27Xc0jk="
  crossorigin="anonymous"></script>
<script src="//netdna.bootstrapcdn.com/bootstrap/3.1.0/js/bootstrap.min.js"></script>


<script type="text/javascript" src="${path}/resources/js/js.cookie.js"></script>
<script type="text/javascript">
$(document).ready(function()
	    {
	        var userId = getCookie("cookieUserId"); 
	        $("input[name='username']").val(userId); 
	         
	        if($("input[name='username']").val() != ""){ // Cookie에 만료되지 않은 아이디가 있어 입력됬으면 체크박스가 체크되도록 표시
	            $("input[name='remember']").attr("checked", true);
	        }
	         
	        $("button[type='submit']", $('.omb_loginForm')).click(function(){ // Login Form을 Submit할 경우,
	            if($("input[name='remember']").is(":checked")){ // ID 기억하기 체크시 쿠키에 저장
	                var userId = $("input[name='username']").val();
	                setCookie("cookieUserId", userId, 7); // 7일동안 쿠키 보관
	            } else {
	                deleteCookie("cookieUserId");
	            }
	        });             
	    })
	 
	    function setCookie(cookieName, value, exdays){
	        var exdate = new Date();
	        exdate.setDate(exdate.getDate()+exdays);
	        var cookieValue = escape(value)+((exdays==null)? "": "; expires="+exdate.toGMTString());
	        document.cookie = cookieName+"="+cookieValue;
	    }
	    function deleteCookie(cookieName){
	        var expireDate = new Date();
	        expireDate.setDate(expireDate.getDate()-1);
	        document.cookie = cookieName+"= "+"; expires="+expireDate.toGMTString();
	    }
	    function getCookie(cookieName){
	        cookieName = cookieName + '=';
	        var cookieData = document.cookie;
	        var start = cookieData.indexOf(cookieName);
	        var cookieValue = '';
	        if(start != -1){
	            start += cookieName.length;
	            var end = cookieData.indexOf(';', start);
	            if(end == -1) end = cookieData.length;
	            cookieValue = cookieData.substring(start, end);
	        }
	        return unescape(cookieValue);
	         
	    }

</script>
<link rel="stylesheet" type="text/css" href="${path}/resources/bootstrap-social-gh-pages/bootstrap-social.css">
<link rel="stylesheet" type="text/css" href="${path}/resources/bootstrap-social-gh-pages/assets/css/font-awesome.css">

<style>
      .login { 
        position: absolute;
        
        top: 150px;
      }
      
      
      html, body {

    margin: 0;

    height: 100%;

    overflow: hidden;

}

    </style>




<title>Insert title here</title>
</head>
<body>
<div class="container">
    

    <div class="omb_login">
    	<h3 class="omb_authTitle">Login or <a href="/join">Sign up</a></h3>
		<div class="row omb_row-sm-offset-3 omb_socialButtons">
    	    <div class="col-xs-4 col-sm-2">
		        <a href="" class="btn btn-block btn-social btn-lg btn-kakao">
			        <i class="fa fa-kakao visible-xs"></i>
			        <span class="hidden-xs">Kakao</span>
		        </a>
	        </div>
        	<div class="col-xs-4 col-sm-2">
		        <a href="#" class="btn btn-lg btn-block omb_btn-facebook">
			        <i class="fa fa-facebook visible-xs"></i>
			        <span class="hidden-xs">Facebook</span>
		        </a>
	        </div>	
        	<div class="col-xs-4 col-sm-2">
		        <a href="#" class="btn btn-lg btn-block omb_btn-google">
			        <i class="fa fa-google-plus visible-xs"></i>
			        <span class="hidden-xs">Google+</span>
		        </a>
	        </div>	
		</div>

		<div class="row omb_row-sm-offset-3 omb_loginOr">
			<div class="col-xs-12 col-sm-6">
				<hr class="omb_hrOr">
				<span class="omb_spanOr">or</span>
			</div>
		</div>

		<div class="row omb_row-sm-offset-3">
			<div class="col-xs-12 col-sm-6">	
			    <form action="/login" class="omb_loginForm" action="" autocomplete="off" method="POST">
					<div class="input-group">
						<span class="input-group-addon"><i class="fa fa-user"></i></span>
						<input id="username" type="text" class="form-control" name="username" placeholder="USER NAME">
					</div>
					<span class="help-block"></span>
										
					<div class="input-group">
						<span class="input-group-addon"><i class="fa fa-lock"></i></span>
						<input   type="password" class="form-control" name="password" placeholder="PASSWORD">
					</div>
					<c:if test = "${result == 0}">
                    <span class="help-block">로그인 실패</span>
					</c:if>
					<div>
					<button id="loginBtn" class="btn btn-lg btn-primary btn-block login" type="submit">Login</button>
					</div>
				</form>
			</div>
    	</div>
		<div class="row omb_row-sm-offset-3 rme">
			<div class="col-xs-12 col-sm-3">
				<label class="checkbox">
					<input id="idSaveCheck" type="checkbox" value="remember-me" name="remember">Remember Me
				</label>
			</div>
			<div class="col-xs-12 col-sm-3">
				<p class="omb_forgotPwd">
					<a href="#">Forgot password?</a>
				</p>
			</div>
		</div>	    	
	</div>



        </div>
</body>
</html>