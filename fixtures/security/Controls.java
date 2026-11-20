// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, compile, or install dependencies.
// There is no entry point, database, servlet container, or supplied payload.
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.sql.SQLException;

class Controls {
    void vulnerable(HttpServletRequest request, Statement statement) throws SQLException {
        String supplied = request.getParameter("fixture_name");
        String sql = "SELECT label FROM fixture_items WHERE label = '" + supplied + "'";
        // ruleid: localguard.security.java-servlet-jdbc-query
        statement.executeQuery(sql);
    }

    void vulnerableJakarta(jakarta.servlet.http.HttpServletRequest request,
                           java.sql.Statement statement) throws SQLException {
        String supplied = request.getParameter("fixture_name");
        String sql = "SELECT label FROM fixture_items WHERE label = '" + supplied + "'";
        // ruleid: localguard.security.java-servlet-jdbc-query
        statement.execute(sql);
    }

    void cleanBound(HttpServletRequest request, Connection connection) throws SQLException {
        String supplied = request.getParameter("fixture_name");
        PreparedStatement statement = connection.prepareStatement(
            "SELECT label FROM fixture_items WHERE label = ?");
        // ok: localguard.security.java-servlet-jdbc-query
        statement.setString(1, supplied);
        // ok: localguard.security.java-servlet-jdbc-query
        statement.executeQuery();
    }

    void cleanConstant(HttpServletRequest request, Statement statement) throws SQLException {
        String unused = request.getParameter("fixture_name");
        // ok: localguard.security.java-servlet-jdbc-query
        statement.executeQuery("SELECT label FROM fixture_items");
    }

    void cleanUnrelated(HttpServletRequest request, FixtureRenderer renderer) {
        String supplied = request.getParameter("fixture_name");
        // ok: localguard.security.java-servlet-jdbc-query
        renderer.executeQuery(supplied);
    }
}

interface FixtureRenderer {
    void executeQuery(String text);
}
