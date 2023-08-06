package com.angelwhu.util;

import java.util.LinkedList;
import java.util.List;

public class StackTrace {
    /**
     * 获取栈信息
     *
     * @return 栈信息
     */
    public static String getStackTrace() {

        Throwable throwable = new Throwable();
        StackTraceElement[] stackTraceElements = throwable.getStackTrace();
        StringBuilder retStack = new StringBuilder();

        for (int i = 0; i < stackTraceElements.length; i++) {
            retStack.append(stackTraceElements[i].getClassName() + "@" + stackTraceElements[i].getMethodName()
                    + "(" + stackTraceElements[i].getLineNumber() + ")" + "\n");
        }

        return retStack.toString();
    }

    /**
     * 获取原始栈
     *
     * @return 原始栈
     */
    public static List<String> getStackTraceArray(int startIndex, int depth) {

        LinkedList<String> stackTrace = new LinkedList<String>();
        Throwable throwable = new Throwable();
        StackTraceElement[] stackTraceElements = throwable.getStackTrace();

        if (stackTraceElements != null) {
            for (int i = startIndex; i < stackTraceElements.length; i++) {
                if (i > startIndex + depth) {
                    break;
                }
                stackTrace.add(stackTraceElements[i].getClassName() + "." + stackTraceElements[i].getMethodName());
            }
        }

        return stackTrace;
    }
}
