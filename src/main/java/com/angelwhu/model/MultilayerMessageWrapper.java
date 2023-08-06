package com.angelwhu.model;

import com.alibaba.fastjson.JSON;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author angelwhu
 * Time: 2018/04/24
 * 针对多层次拦截，封装ABCD各个层次的消息Model.
 */

public class MultilayerMessageWrapper {

    private final Logger multilayerLogger = LoggerFactory.getLogger("MULTILAYER-MESSAGE-LOGGER");

    private AHTTPServletLayerMessage aHTTPServletLayerMessage;
    private BApplicationLayerMessage bApplicationLayerMessage;
    private CExpressionLayerMessage cExpressionLayerMessage;
    private DBehaviorLayerMessage dBehaviorLayerMessage;

    public MultilayerMessageWrapper() {
        setaHTTPServletLayerMessage(new AHTTPServletLayerMessage());
        setbApplicationLayerMessage(new BApplicationLayerMessage());
        setcExpressionLayerMessage(new CExpressionLayerMessage());
        setdBehaviorLayerMessage(new DBehaviorLayerMessage());
    }

    public AHTTPServletLayerMessage getaHTTPServletLayerMessage() {
        return aHTTPServletLayerMessage;
    }

    public void setaHTTPServletLayerMessage(AHTTPServletLayerMessage aHTTPServletLayerMessage) {
        this.aHTTPServletLayerMessage = aHTTPServletLayerMessage;
    }

    public BApplicationLayerMessage getbApplicationLayerMessage() {
        return bApplicationLayerMessage;
    }

    public void setbApplicationLayerMessage(BApplicationLayerMessage bApplicationLayerMessage) {
        this.bApplicationLayerMessage = bApplicationLayerMessage;
    }

    public CExpressionLayerMessage getcExpressionLayerMessage() {
        return cExpressionLayerMessage;
    }

    public void setcExpressionLayerMessage(CExpressionLayerMessage cExpressionLayerMessage) {
        this.cExpressionLayerMessage = cExpressionLayerMessage;
    }

    public DBehaviorLayerMessage getdBehaviorLayerMessage() {
        return dBehaviorLayerMessage;
    }

    public void setdBehaviorLayerMessage(DBehaviorLayerMessage dBehaviorLayerMessage) {
        this.dBehaviorLayerMessage = dBehaviorLayerMessage;
    }

    /**
     * Format all information to json. @angelwhu 2018/04/25
     */
    public void storeMultilayerMessages()
    {
        multilayerLogger.info(JSON.toJSONString(this));
    }

    @Override
    public String toString() {
        return JSON.toJSONString(this);
    }
}
