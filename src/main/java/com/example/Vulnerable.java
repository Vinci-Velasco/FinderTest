// VulnerableServer.java
package com.example;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Map;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Vulnerable extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String userRequest = cookieValue(req, "request");

        // ===== VULNERABLE PATTERN (CWE-78) =====
        // Concatenate attacker-controlled input into a single command string.
        // Passing this string into Runtime.exec(String) can lead to command injection.
        String cmd = "/usr/bin/mytool " + userRequest;
        Runtime.getRuntime().exec(cmd);
        Runtime.getRuntime().exec("mytool arg1 arg2");
        Runtime.getRuntime().exec("mytool arg1 arg2 " + userRequest);

        resp.setContentType("text/plain");
        try (PrintWriter w = resp.getWriter()) {
            w.println("VULN OUTPUT:");
            w.println(out.toString());
        }
    }

    private String cookieValue(HttpServletRequest req, String name) {
        Cookie[] cookies = req.getCookies(); // <-- your requested API
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) return c.getValue();
        }
        return null;
    }
}