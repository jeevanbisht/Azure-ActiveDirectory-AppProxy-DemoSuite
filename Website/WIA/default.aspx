<%@ Page Language="C#" %>
<%@ Import Namespace="System.Web.Security" %>


<html>
<head id="Head1" runat="server">
  <title>App Proxy - WIA  Sample</title>
<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial;
    font-size: 17px;
    background: url(back.jpg) no-repeat center center fixed; 
	-webkit-background-size: cover;
  -moz-background-size: cover;
  -o-background-size: cover;
  background-size: cover;
}

div.fixed {
    font-family: "Times New Roman";
    font-size: 24px;
	color: white;
    position: fixed;
    top : 10;
    right: 10;
    width: 300px;
    border: 3px solid #73AD21;
	padding-left: 5px;
}


.content1 {
    position: fixed;
    top: 0;
    background: rgba(0, 0, 0, 0.5);
    color: #f1f1f1;
    width: 100%;
    padding: 40px;
}


.content {
    position: fixed;
	text-align: left;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    color: #f1f1f1;
    width: 100%;
    padding: 30px;
}

</style>
  
  
</head>

   <div class="content1" >
   
   </div>
	
	<div class="fixed" >
	
	Welcome <%=User.Identity.Name.ToLower()%>

	</div>

  
  <div class="content" >
  <img src="logo.png">  
  </div>
</body>
</html>