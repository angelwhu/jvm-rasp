package com.angelwhu.model;

import com.angelwhu.alarm.AlarmSendMailThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author angelwhu
 * Time: 2018/04/24
 * 漏洞攻击判定结果Model.
 */

public class JudgeResult {

    private final Logger judgeLogger = LoggerFactory.getLogger("ALARM-ATTACK-LOGGER");

    public enum AttackType{
        rceAttack,SQLInjectAttack,ServerConfigError
    }
    public enum RiskLevel{
        HIGH,MEDIUM,LOW
    }

    private Boolean attack;         //攻击是否成功的标记
    private AttackType attackType;  //何种类型攻击
    private RiskLevel riskLevel;    //威胁等级
    private String resultMessage;   //结果信息


    public Boolean getAttack() {
        return attack;
    }

    public void setAttack(Boolean attack) {
        this.attack = attack;
    }

    public String getResultMessage() {
        return resultMessage;
    }

    public void setResultMessage(String resultMessage) {
        this.resultMessage = resultMessage;
    }

    public AttackType getAttackType() {
        return attackType;
    }

    public void setAttackType(AttackType attackType) {
        this.attackType = attackType;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public void processJudgeResult(MultilayerMessageWrapper multilayerMessageWrapper, String stackTrace)
    {
        if(!attack)
        {
            return;
        }


        String alarmMessage = "";

        if(attackType == null)
        {
            alarmMessage = alarmMessage + "攻击类型：未知;";
        }
        switch (attackType)
        {
            case rceAttack: alarmMessage = alarmMessage + "攻击类型：远程代码执行;";
                break;
            case SQLInjectAttack: alarmMessage = alarmMessage + "攻击类型：SQL注入攻击;";
                break;
            default: break;
        }

        /**
         * ToDo: 根据威胁等级，采用不同的告警方式.
         */
        if(riskLevel == null)
        {
            alarmMessage = alarmMessage + "威胁等级：未知;";
        }
        alarmMessage = alarmMessage + "攻击信息：" + resultMessage + ";";

        switch (riskLevel){
            case HIGH: alarmMessage = alarmMessage + "威胁等级：高;";
                /**
                 * Send Email to admin.  alarmMessage + multilayerMessage + stackTrace.
                 */
                String content = alarmMessage + "\n" + "各层次拦截信息：" + multilayerMessageWrapper + "\n" + "Java堆栈信息：" + stackTrace;
                AlarmSendMailThread alarmSendMailThread = new AlarmSendMailThread();
                alarmSendMailThread.setEmailSubject("RASP告警");
                alarmSendMailThread.setEmailContent(content);
                new Thread(alarmSendMailThread).start();
                break;
            case MEDIUM: alarmMessage = alarmMessage + "威胁等级：中;";
                break;
            case LOW: alarmMessage = alarmMessage + "威胁等级：低;";
                break;
            default: break;
        }
        judgeLogger.info(alarmMessage);
        /**
         * ToDo: 使用数据库或其他消息中间件进行消息的分发存储. 将所有（ABCD层次）和（简要判定结果信息）存储在数据库，提供可视化阅读. 使用UUID标识2个表的一致关系. @angelwhu 2018/05/02
         */
    }
}
