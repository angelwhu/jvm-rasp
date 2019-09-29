package com.angelwhu.model;

/**
 * @author angelwhu
 * Time: 2018/04/24
 * D层行为监控层消息Model.
 */

public class DBehaviorLayerMessage {
    public enum Behavior{
        executeCMD,readFile,writeFile,queryDB
    }

    private Behavior behavior; //行为
    private String message;    //行为对应关键参数信息。如：执行的命令，读写的文件。

    public Behavior getBehavior() {
        return behavior;
    }

    public void setBehavior(Behavior behavior) {
        this.behavior = behavior;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    /**
     * ToDo: Add stacktrace information field. @angelwhu 2018/04/25
     */
}
