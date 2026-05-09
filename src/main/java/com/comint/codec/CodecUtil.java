package com.comint.codec;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Locale;

public final class CodecUtil {

    private CodecUtil() {}

    public static String safeContentType(HttpRequest request) {
        if (request == null) return "";
        try {
            String v = request.headerValue("Content-Type");
            return v == null ? "" : v.toLowerCase(Locale.ROOT).trim();
        } catch (Throwable e) {
            return "";
        }
    }

    public static String safeContentType(HttpResponse response) {
        if (response == null) return "";
        try {
            String v = response.headerValue("Content-Type");
            return v == null ? "" : v.toLowerCase(Locale.ROOT).trim();
        } catch (Throwable e) {
            return "";
        }
    }

    public static String safeHeader(HttpRequest request, String name) {
        if (request == null || name == null || name.isEmpty()) return "";
        try {
            String v = request.headerValue(name);
            return v == null ? "" : v;
        } catch (Throwable e) {
            return "";
        }
    }

    public static String safePath(HttpRequest request) {
        if (request == null) return "";
        try {
            String p = request.path();
            return p == null ? "" : p;
        } catch (Throwable e) {
            return "";
        }
    }

    public static String safeMethod(HttpRequest request) {
        if (request == null) return "";
        try {
            String m = request.method();
            return m == null ? "" : m.toUpperCase(Locale.ROOT);
        } catch (Throwable e) {
            return "";
        }
    }

    public static int safeBodyLength(HttpRequest request) {
        if (request == null) return 0;
        try {
            return request.body() == null ? 0 : request.body().length();
        } catch (Throwable e) {
            return 0;
        }
    }

    public static int safeBodyLength(HttpResponse response) {
        if (response == null) return 0;
        try {
            return response.body() == null ? 0 : response.body().length();
        } catch (Throwable e) {
            return 0;
        }
    }

    public static byte[] safeBodyBytes(HttpRequest request) {
        if (request == null) return new byte[0];
        try {
            if (request.body() == null) return new byte[0];
            byte[] b = request.body().getBytes();
            return b == null ? new byte[0] : b;
        } catch (Throwable e) {
            return new byte[0];
        }
    }

    public static byte[] safeBodyBytes(HttpResponse response) {
        if (response == null) return new byte[0];
        try {
            if (response.body() == null) return new byte[0];
            byte[] b = response.body().getBytes();
            return b == null ? new byte[0] : b;
        } catch (Throwable e) {
            return new byte[0];
        }
    }

    public static boolean contentTypeContains(String contentType, String needle) {
        if (contentType == null || needle == null) return false;
        if (contentType.isEmpty() || needle.isEmpty()) return false;
        if (contentType.length() < needle.length()) return false;
        return contentType.contains(needle);
    }

    public static boolean pathContains(String path, String needle) {
        if (path == null || needle == null) return false;
        if (path.isEmpty() || needle.isEmpty()) return false;
        if (path.length() < needle.length()) return false;
        return path.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));
    }

    public static String preview(byte[] data, int max) {
        if (data == null || data.length == 0) return "";
        if (max <= 0) return "";
        int n = Math.min(max, data.length);
        return new String(data, 0, n);
    }
}
