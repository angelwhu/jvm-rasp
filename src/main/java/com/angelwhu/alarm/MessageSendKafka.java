package com.angelwhu.alarm;

/**
 * @author angelwhu
 * 2018/05/07
 */

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.Producer;
import org.apache.kafka.clients.producer.ProducerRecord;

import java.util.Properties;
import java.util.UUID;

/**
 * User thread to send message to kafka. @angelwhu 2018/05/07
 */

public class MessageSendKafka {

    /**
     * Singleton design pattern. @angelwhu 2018/05/07
     */
    private static class MessageSendKafkaHolder
    {
        private static final MessageSendKafka INSTANCE = new MessageSendKafka();
    }

    public static final MessageSendKafka getInstance()
    {
        return MessageSendKafkaHolder.INSTANCE;
    }

    private Producer<String, String> producer;

    private MessageSendKafka()
    {
        Properties props = new Properties();
        props.put("bootstrap.servers", KafkaProperty.Bootstrap_servers);
        props.put("acks", "all");
        props.put("retries", 0);
        props.put("batch.size", 16384);
        props.put("linger.ms", 1);
        props.put("buffer.memory", 33554432);
        props.put("key.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        props.put("value.serializer", "org.apache.kafka.common.serialization.StringSerializer");
        producer = new KafkaProducer<String,String>(props);
    }

    /**
     * 消息发送~
     */
    public void sendMessage(String messageContent){
        String uid = UUID.randomUUID().toString();
        System.out.println(uid);
        producer.send(new ProducerRecord<String, String>("rasp",uid,messageContent));
    }

    public static void main(String[] args) throws InterruptedException {
        while (true)
        {
            Thread.sleep(5000);
            MessageSendKafka.getInstance().sendMessage("2018-05-02 00:00:22 INFO  {\"aHTTPServletLayerMessage\":{\"httpAccess\":{\"beginTimestamp\":1525244407849,\"from\":\"192.168.136.1\",\"method\":\"POST\",\"parameterMap\":{\"page\":[\"\"],\"size\":[\"5\"],\"username[#this.getClass().forName(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"gnome-calculator\\\")]\":[\"angelwhu\"],\"password\":[\"123456\"],\"repeatedPassword\":[\"123456\"]},\"status\":0,\"uri\":\"/users\",\"userAgent\":\"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0\"},\"httpServerType\":\"tomcat\"},\"bApplicationLayerMessage\":{\"applicationType\":\"springmvc\",\"mapping\":\"public java.lang.Object example.users.web.UserController.register(example.users.web.UserController$UserForm,org.springframework.validation.BindingResult,org.springframework.ui.Model)\"},\"cExpressionLayerMessage\":{\"expression\":\"username[#this.getClass().forName(\\\"java.lang.Runtime\\\").getRuntime().exec(\\\"gnome-calculator\\\")]\",\"languageType\":\"SpEL\"},\"dBehaviorLayerMessage\":{\"behavior\":\"executeCMD\",\"message\":\"gnome-calculator\"}}");
        }
    }

}
