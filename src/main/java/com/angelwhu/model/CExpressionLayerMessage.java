package com.angelwhu.model;

/**
 * @author angelwhu
 * Time: 2018/04/24
 * C层表达式语言层消息Model.
 */

public class CExpressionLayerMessage {
    public enum LanguageType{
        OGNL,SpEL
    }

    private LanguageType languageType;
    private String expression;
    /*
    * ToDo: Expression should be an array. @angelwhu 2018/05/02
    * */

    public LanguageType getLanguageType() {
        return languageType;
    }

    public void setLanguageType(LanguageType languageType) {
        this.languageType = languageType;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }
}
