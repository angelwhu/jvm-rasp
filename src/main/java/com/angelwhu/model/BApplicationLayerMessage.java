package com.angelwhu.model;

/**
 * @author angelwhu
 * Time: 2018/04/24
 * B层应用程序层消息Model.
 */

public class BApplicationLayerMessage {
    public enum ApplicationType {
        struts2, springmvc
    }

    private ApplicationType applicationType;
    private String mapping;

    public ApplicationType getApplicationType() {
        return applicationType;
    }

    public void setApplicationType(ApplicationType applicationType) {
        this.applicationType = applicationType;
    }

    public String getMapping() {
        return mapping;
    }

    public void setMapping(String mapping) {
        this.mapping = mapping;
    }
}
