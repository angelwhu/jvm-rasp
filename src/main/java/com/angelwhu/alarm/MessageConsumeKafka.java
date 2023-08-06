package com.angelwhu.alarm;

/**
 * @author angelwhu
 * 2018/05/07
 */

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;


import java.util.Arrays;
import java.util.Properties;


/**
 * User thread to consume message to kafka. @angelwhu 2018/05/07
 */

public class MessageConsumeKafka {

    /**
     * Singleton design pattern. @angelwhu 2018/05/07
     */
    private static class MessageConsumeKafkaHolder
    {
        private static final MessageConsumeKafka INSTANCE = new MessageConsumeKafka();
    }

    public static final MessageConsumeKafka getInstance()
    {
        return MessageConsumeKafkaHolder.INSTANCE;
    }

    private KafkaConsumer<String, String> consumer;

    private MessageConsumeKafka()
    {
        Properties props = new Properties();
        props.put("bootstrap.servers", KafkaProperty.Bootstrap_servers);
        props.put("group.id", "test");
        props.put("enable.auto.commit", "true");
        props.put("auto.commit.interval.ms", "1000");
        props.put("key.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        props.put("value.deserializer", "org.apache.kafka.common.serialization.StringDeserializer");
        consumer = new KafkaConsumer<String, String>(props);
        consumer.subscribe(Arrays.asList("rasp"));
    }

    /**
     * 消息消费~
     */
    public void consumeMessage(){
        while (true) {
            ConsumerRecords<String, String> records = consumer.poll(100);
            for (ConsumerRecord<String, String> record : records)
                System.out.printf("offset = %d, key = %s, value = %s%n", record.offset(), record.key(), record.value());
        }
    }

    public static void main(String[] args) {
        MessageConsumeKafka.getInstance().consumeMessage();
    }

}
