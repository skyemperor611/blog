<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt"%>
<c:set var="path" value="${pageContext.request.contextPath}"></c:set>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link rel="stylesheet" type="text/css" href="${path}/resources/css/maincss/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="${path}/resources/css/maincss/bootstrap.css">
<link rel="stylesheet" type="text/css" href="${path}/resources/css/maincss/style.css">
<style>
         
      html, body {

    margin: 0;

    height: 100%;

    overflow: hidden;

}

    </style>

<title>Insert title here</title>
</head>
<div class="container">
<jsp:include page="layout/topLayout.jsp" flush="false" /> 
<body>

	
    <div class="container-fluid pt-5">
	<div class="row">
		<div class="col-md-12">
			
			<table class="table table-striped table-bordered table-hover">
				<thead>
					<tr>
						<th scope="col" class="text-center">
							게시글 번호
						</th>
						<th scope="col" class="text-center">
							제목
						</th>
						<th scope="col" class="text-center">
							게시자
						</th>
						<th scope="col" class="text-center">
							조회수
						</th>
						<th scope="col" class="text-center">
							작성일
						</th>
					</tr>
				</thead>
				<tbody>
				<c:forEach var="list" items="${list }">
					<tr>
						<th scope="col" class="text-center"> <c:out value="${list.boardid }"></c:out></th>
						<th scope="col" class="text-center"> <c:out value="${list.title }"></c:out></th>
						<th scope="col" class="text-center"> <c:out value="${list.username }"></c:out></th>
						<th scope="col" class="text-center"> <c:out value="${list.count }"></c:out></th>
						<th scope="col" class="text-center"> <c:out value="${list.createDate }"></c:out></th>
					</tr>
				</c:forEach>
					
				</tbody>
			</table>
			<nav>
				<ul class="pagination pt-10">
					<li class="page-item">
						<a class="page-link" href="#">Previous</a>
					</li>
					<li class="page-item">
						<a class="page-link" href="#">1</a>
					</li>
					<li class="page-item">
						<a class="page-link" href="#">2</a>
					</li>
					<li class="page-item">
						<a class="page-link" href="#">3</a>
					</li>
					<li class="page-item">
						<a class="page-link" href="#">4</a>
					</li>
					<li class="page-item">
						<a class="page-link" href="#">5</a>
					</li>
					<li class="page-item">
						<a class="page-link" href="#">Next</a>
					</li>
				</ul>
			</nav> 
			<address>
				 <strong>Twitter, Inc.</strong><br> 795 Folsom Ave, Suite 600<br> San Francisco, CA 94107<br> <abbr title="Phone">P:</abbr> (123) 456-7890
			</address>
		</div>
	</div>
</body>
</div>
<script type="text/javascript" src="${path}/resources/js/jquery.min.js"></script>
<script type="text/javascript" src="${path}/resources/js/bootstrap.min.js"></script>
<script type="text/javascript" src="${path}/resources/js/popper.min.js"></script>
</html>