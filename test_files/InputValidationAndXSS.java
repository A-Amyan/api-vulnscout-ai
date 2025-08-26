// File: InputValidationAndXSS.java
// Contains input validation failures and XSS vulnerabilities
import javax.servlet.http.*;
import java.io.*;
import java.util.regex.*;
import javax.servlet.ServletException;

public class InputValidationAndXSS extends HttpServlet {
    
    // Direct output of user input - XSS vulnerability
    protected void doGet(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        String userInput = request.getParameter("message");
        PrintWriter out = response.getWriter();
        
        // VULNERABLE - direct output without escaping
        out.println("<html><body>");
        out.println("<h1>Your message: " + userInput + "</h1>");
        out.println("</body></html>");
    }
    
    // Path traversal vulnerability
    public String readUserFile(String filename) throws IOException {
        // VULNERABLE - no path validation, allows directory traversal
        File file = new File("/uploads/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line).append("\n");
        }
        reader.close();
        return content.toString();
    }
    
    // Command injection vulnerability
    public String executeSystemCommand(String userCommand) throws IOException {
        // VULNERABLE - direct execution of user input
        Process process = Runtime.getRuntime().exec("cmd /c " + userCommand);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }
    
    // Regex injection and ReDoS vulnerability
    public boolean validateUserInput(String pattern, String input) {
        try {
            // VULNERABLE - user controls regex pattern, potential ReDoS
            Pattern regex = Pattern.compile(pattern);
            return regex.matcher(input).matches();
        } catch (Exception e) {
            return false;
        }
    }
    
    // Weak input validation
    public boolean isValidEmail(String email) {
        // VULNERABLE - extremely weak validation
        return email != null && email.contains("@") && email.contains(".");
    }
    
    // Missing authorization check
    public void deleteUserAccount(HttpServletRequest request) throws IOException {
        String targetUserId = request.getParameter("userId");
        String currentUser = (String) request.getSession().getAttribute("username");
        
        // VULNERABLE - no authorization check if user can delete the target account
        deleteUser(targetUserId);
    }
    
    // Unsafe file upload handling
    public void handleFileUpload(HttpServletRequest request) throws Exception {
        String filename = request.getParameter("filename");
        String content = request.getParameter("content");
        
        // VULNERABLE - no file type validation, allows executable uploads
        File uploadFile = new File("/uploads/" + filename);
        FileWriter writer = new FileWriter(uploadFile);
        writer.write(content);
        writer.close();
    }
    
    // LDAP injection vulnerability
    public String searchLDAP(String username) {
        // VULNERABLE - LDAP injection
        String filter = "(&(objectClass=person)(uid=" + username + "))";
        // Simulated LDAP search would use this filter
        return "ldap://server/search?filter=" + filter;
    }
    
    // XML External Entity (XXE) vulnerability
    public String parseXMLInput(String xmlContent) throws Exception {
        // VULNERABLE - XXE processing enabled
        javax.xml.parsers.DocumentBuilderFactory factory = 
            javax.xml.parsers.DocumentBuilderFactory.newInstance();
        // Missing security features to prevent XXE
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        org.w3c.dom.Document doc = builder.parse(
            new java.io.ByteArrayInputStream(xmlContent.getBytes())
        );
        return doc.getDocumentElement().getTextContent();
    }
    
    private void deleteUser(String userId) {
        // Simulated user deletion
        System.out.println("Deleting user: " + userId);
    }
}