<%@ Page Language="C#" %>
<%@ Import Namespace="System.Web.Security" %>

<script runat="server">
  void Logon_Click(object sender, EventArgs e)
  {
    if ((UserEmail.Text == "test") && 
            (UserPass.Text == "test"))
      {
          FormsAuthentication.RedirectFromLoginPage 
             (UserEmail.Text, Persist.Checked);
      }
      else
      {
          Msg.Text = "Invalid credentials. Please try again.";
      }
  }
</script>
<html>
<head id="Head1" runat="server">
  <title>App Proxy - Forms Authentication Sample</title>
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


.content {
    position: fixed;
    bottom: 0;
    background: rgba(0, 0, 0, 0.5);
    color: #f1f1f1;
    width: 100%;
    padding: 30px;
}

</style>
  
  
</head>

<img src="logo.png">
  <form id="form1" runat="server">
    <font color="#f7f4f5">	
	<h2>
      Logon Page</h2>
	  </font>
    <table>
	
      <tr>
        <td>
          <font color="#f7f4f5">	UserName :</td> </font>
        <td>
          <asp:TextBox ID="UserEmail" runat="server" /></td>
        <td>
          <asp:RequiredFieldValidator ID="RequiredFieldValidator1" 
            ControlToValidate="UserEmail"
            Display="Dynamic" 
            ErrorMessage="Cannot be empty." 
            runat="server" />
        </td>
      </tr>
      <tr>
        <td>
          <font color="#f7f4f5"> Password:</td> </font>
        <td>
          <asp:TextBox ID="UserPass" TextMode="Password" 
             runat="server" />
        </td>
        <td>
          <asp:RequiredFieldValidator ID="RequiredFieldValidator2" 
            ControlToValidate="UserPass"
            ErrorMessage="Cannot be empty." 
            runat="server" />
        </td>
      </tr>
      <tr>
        <td>
          Remember me?</td>
        <td>
          <asp:CheckBox ID="Persist" runat="server" /></td>
      </tr>
    </table>
	  
    <asp:Button ID="Submit1" OnClick="Logon_Click" Text="Log On" 
       runat="server" />
    <p>
      <asp:Label ID="Msg" ForeColor="red" runat="server" />
    </p>
  </form>
  
  
  <div class="content" >
  Contoso Expense @ 2018 
  </div>
</body>
</html>