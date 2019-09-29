package com.angelwhu.model;

import java.util.Map;

/**
 * @author angelwhu
 * Time: 2018/04/24
 * A层HTTP服务器层消息Model.
 */

public class AHTTPServletLayerMessage {

    public class AHttpAccess {
        private String from;
        private String method;
        private String uri;
        private Map<String, String[]> parameterMap;
        private String userAgent;
        private int status;
        private long beginTimestamp;
        private String cookie;

        public String getCookie() {
            return cookie;
        }

        public void setCookie(String cookie) {
            this.cookie = cookie;
        }

        public String getFrom() {
            return from;
        }

        public void setFrom(String from) {
            this.from = from;
        }

        public String getMethod() {
            return method;
        }

        public void setMethod(String method) {
            this.method = method;
        }

        public String getUri() {
            return uri;
        }

        public void setUri(String uri) {
            this.uri = uri;
        }

        public Map<String, String[]> getParameterMap() {
            return parameterMap;
        }

        public void setParameterMap(Map<String, String[]> parameterMap) {
            this.parameterMap = parameterMap;
        }

        public String getUserAgent() {
            return userAgent;
        }

        public void setUserAgent(String userAgent) {
            this.userAgent = userAgent;
        }

        public int getStatus() {
            return status;
        }

        public void setStatus(int status) {
            this.status = status;
        }

        public long getBeginTimestamp() {
            return beginTimestamp;
        }

        public void setBeginTimestamp(long beginTimestamp) {
            this.beginTimestamp = beginTimestamp;
        }
    }
    public enum HttpServerType{
        tomcat, jetty
    }

    private HttpServerType httpServerType;
    private AHttpAccess httpAccess;
    private String message;

    public AHTTPServletLayerMessage() {
        this.httpAccess = new AHttpAccess();
    }

    public HttpServerType getHttpServerType() {
        return httpServerType;
    }

    public void setHttpServerType(HttpServerType httpServerType) {
        this.httpServerType = httpServerType;
    }

    public AHttpAccess getHttpAccess() {
        return httpAccess;
    }

    public void setHttpAccess(AHttpAccess httpAccess) {
        this.httpAccess = httpAccess;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

}

