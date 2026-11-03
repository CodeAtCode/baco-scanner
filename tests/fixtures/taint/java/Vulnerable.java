// Vulnerable: SQL injection via user input
import java.sql.*;
import javax.servlet.http.*;

public class Vulnerable {
    public void handleRequest(HttpServletRequest request) throws SQLException {
        String sql = request.getParameter("query");
        Statement stmt = connection.createStatement();
        stmt.executeQuery(sql);
    }
}
