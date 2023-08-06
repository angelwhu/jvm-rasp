package com.angelwhu.alarm;

import org.apache.commons.lang3.reflect.MethodUtils;

import java.lang.reflect.InvocationTargetException;

public class ResponseProcess {

    private Object response;

    public ResponseProcess(Object response) {
        this.response = response;
    }

    public Object getResponse() {
        return response;
    }

    public void setResponse(Object response) {
        this.response = response;
    }

    public void sendAlarmToViews(String content) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        Object printer = null;

        printer = MethodUtils.invokeMethod(response, "getWriter");
        if (printer == null) {
            printer = MethodUtils.invokeMethod(response, "getOutputStream");
        }
        MethodUtils.invokeMethod(printer, "print", content);
        MethodUtils.invokeMethod(printer, "flush");
        MethodUtils.invokeMethod(printer, "close");

    }
}
