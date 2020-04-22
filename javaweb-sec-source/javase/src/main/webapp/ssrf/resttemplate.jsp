<%@ page import="org.springframework.http.ResponseEntity" %>
<%@ page import="org.springframework.web.client.RestTemplate" %>
<%@ page import="java.net.URI" %>
<%@ page import="java.net.URISyntaxException" %>
<%-- resttemplate.jsp?url=http://burpcollaborator.net --%>
<%
    String url = request.getParameter("url");

    try {
        URI                    uri            = new URI(url);
        RestTemplate           restTemplate   = new RestTemplate();
        ResponseEntity<String> responseEntity = restTemplate.getForEntity(uri, String.class);
        out.write(responseEntity.getBody());
    } catch (URISyntaxException e) {
        e.printStackTrace();
    }

%>