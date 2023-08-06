package com.angelwhu.alarm;

import org.apache.commons.mail.SimpleEmail;

/**
 * @author angelwhu
 * 2018/05/02
 */

/**
 * User thread to send mail. @angelwhu 2018/05/02
 */

public class AlarmSendMailThread implements Runnable{

    private static final String HOSTNAME = "smtp.qq.com";
    public static final String POP_USERNAME = "***@qq.com";//此设置发送邮件的邮箱
    private static final String USERNAME = "RASP"; // 设置发件邮箱的显示名
    private static final String POP_PASSWORD = "***";//邮箱的授权码
    private static final String CODING = "UTF-8";

    private String adminEmail = "***@163.com";
    private String emailSubject = "";
    private String emailContent = "";

    public String getAdminEmail() {
        return adminEmail;
    }

    public void setAdminEmail(String adminEmail) {
        this.adminEmail = adminEmail;
    }

    public String getEmailSubject() {
        return emailSubject;
    }

    public void setEmailSubject(String emailSubject) {
        this.emailSubject = emailSubject;
    }

    public String getEmailContent() {
        return emailContent;
    }

    public void setEmailContent(String emailContent) {
        this.emailContent = emailContent;
    }


    /**
     * 普通文本邮件
     */
    public void sendEmail(String toEmail,String emailSubject,String emailContent){
        SimpleEmail simpleEmail = new SimpleEmail();
        simpleEmail.setSSLOnConnect(true);
        simpleEmail.setSslSmtpPort("465");
        simpleEmail.setHostName(HOSTNAME);
        simpleEmail.setAuthentication(POP_USERNAME, POP_PASSWORD);
        simpleEmail.setCharset(CODING);

        try {
            simpleEmail.addTo(toEmail);
            simpleEmail.setFrom(POP_USERNAME, USERNAME);
            simpleEmail.setSubject(emailSubject);
            simpleEmail.setMsg(emailContent);
            simpleEmail.send();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void run() {
        sendEmail(adminEmail,emailSubject,emailContent);
    }

    public static void main(String[] args) {
        new AlarmSendMailThread().sendEmail("1149545650@qq.com", "测试发邮件", "Test success.");
    }

}
