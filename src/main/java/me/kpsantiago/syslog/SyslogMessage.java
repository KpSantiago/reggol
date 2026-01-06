package me.kpsantiago.syslog;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SyslogMessage {
     private int priority;
     private int version;
     private OffsetDateTime timestamp;
     private String hostname;
     private String applicationName;
     private long processId;
     private String msgId;
     private String structuredData = "-";
     private String message;

     private String formattedString;

     public static SyslogMessage createFromString(String message) {
         SyslogMessage m = new SyslogMessage();
         message = message.trim();

         String[] parts = message.split(" ", 7);

         Pattern p1 = Pattern.compile("<(\\d+)>");
         Matcher m1 = p1.matcher(parts[0]);

         if(m1.find()) {
             m.setPriority(Integer.parseInt(m1.group(1)));
         }

         m.setVersion(Integer.parseInt(parts[0].split(">")[1]));
         m.setTimestamp(OffsetDateTime.parse(parts[1]));
         m.setHostname(parts[2]);
         m.setApplicationName(parts[3]);
         m.setProcessId(Integer.parseInt(parts[4]));
         m.setMsgId(parts[5]);

         Pattern p2 = Pattern.compile("\\[.*?\\]");
         Matcher m2 = p2.matcher(parts[6]);

         StringBuilder sb = new StringBuilder();
         int end = -1;

         while(m2.find()) {
             sb.append(m2.group());
             end = m2.end();
         }

         m.setStructuredData(!sb.isEmpty() ? sb.toString() : "-");
         if (end == -1) {
             throw new RuntimeException("Was not possible to get message from the log");
         }
         m.setMessage(parts[6].substring(end).trim());
         m.setFormattedString(message);
         return m;
     }
}
