// Vulnerable: SQL injection via user input
using System;
using System.Data.SqlClient;
using System.Web;

public class Vulnerable {
    public void HandleRequest(HttpContext context) {
        string sql = context.Request.QueryString["query"];
        SqlCommand cmd = new SqlCommand(sql);
        cmd.ExecuteNonQuery();
    }
}
