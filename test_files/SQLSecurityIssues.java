// File: SQLSecurityIssues.java
// Contains SQL injection and database security vulnerabilities
import java.sql.*;
import javax.servlet.http.*;

public class SQLSecurityIssues {
    
    // SQL Injection via string concatenation
    public ResultSet getUserData(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        String query = "SELECT * FROM users WHERE id = '" + userId + "'"; // VULNERABLE
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);
    }
    
    // SQL Injection via String.format
    public void loginUser(String username, String password) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        String query = String.format("SELECT * FROM users WHERE username='%s' AND password='%s'", 
                                    username, password); // VULNERABLE
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        
        // Resource leak - connection not properly closed
        // VULNERABLE - resources should be closed in try-with-resources or finally block
    }
    
    // SQL Injection in batch operations
    public void updateUserRoles(HttpServletRequest request) throws SQLException {
        String[] userIds = request.getParameterValues("userIds");
        String newRole = request.getParameter("role");
        
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        
        for (String userId : userIds) {
            // VULNERABLE - SQL injection in batch
            String updateQuery = "UPDATE users SET role = '" + newRole + "' WHERE id = " + userId;
            stmt.addBatch(updateQuery);
        }
        stmt.executeBatch();
    }
    
    // Improper parameterized query usage
    public void searchProducts(String category, String minPrice) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        // VULNERABLE - mixing parameterized and concatenated queries
        String query = "SELECT * FROM products WHERE category = ? AND price > " + minPrice;
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, category);
        ResultSet rs = stmt.executeQuery();
    }
}
