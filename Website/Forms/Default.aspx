<%@ Page Language="C#" %>
<html>
<head>

<title>Forms Authentication - Default Page</title>

<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* {
    box-sizing: border-box;
}

body {
    margin: 0;
    font-family: Arial;
    font-size: 17px;
}

#myVideo {
    position: fixed;
    right: 0;
    bottom: 0;
    min-width: 100%; 
    min-height: 100%;
}

.content {
    position: fixed;
    bottom: 0;
    background: rgba(0, 0, 0, .5);
    color: #f1f1f1;
    width: 100%;
    padding: 50px;
}

.content1 {
    position: fixed;
    bottom: 50;
    background: rgba(0, 0, 0, 0.5);
    color: #f1f1f1;
    width: 100%;
    padding: 20px;
}


#myBtn {
    width: 50px;
    font-size: 12px;
    padding: 10px;
    border: none;
    background: #000;
    color: #fff;
    cursor: pointer;
}

#myBtn:hover {
    background: #ddd;
    color: black;
}
</style>
</head>


<script runat="server">
  void Page_Load(object sender, EventArgs e)
  {
    Welcome.Text = "Hello, " + Context.User.Identity.Name;
  }

  void Signout_Click(object sender, EventArgs e)
  {
    FormsAuthentication.SignOut();
    Response.Redirect("Logon.aspx");
  }
</script>

<body>



<video autoplay muted loop id="myVideo">
  <source src="demo1.mp4" type="video/mp4">
  Your browser does not support HTML5 video.
</video>



<div class="content" >
  <h1>Welcome to Contoso Expense</h1>
<asp:Label ID="Welcome" runat="server" />
  <form id="Form1" runat="server">
    <asp:Button ID="Submit1" OnClick="Signout_Click" 
       Text="Sign Out" runat="server" /><p>
  </form>



 <!-- <button id="myBtn" onclick="myFunction()">Pause</button> -->
</div>
 
<script>
var video = document.getElementById("myVideo");
var btn = document.getElementById("myBtn");


function myFunction() {
  if (video.paused) {
    video.play();
    btn.innerHTML = "Pause";
  } else {
    video.pause();
    btn.innerHTML = "Play";
  }
}
</script>

 
</body>
</html>