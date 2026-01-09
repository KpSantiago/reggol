package me.kpsantiago;

import me.kpsantiago.config.SecureSocketConfig;
import me.kpsantiago.syslog.SyslogMessage;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Reggol {
    public static void main(String[] args) {
        try (
                SSLServerSocket server = (SSLServerSocket) SecureSocketConfig.config().createServerSocket();
        ) {
           server.setNeedClientAuth(true);
           server.bind(new InetSocketAddress("127.0.0.1", 888));

            ExecutorService pool = Executors.newFixedThreadPool(100);

            while (true) {
                SSLSocket client = (SSLSocket) server.accept();
                pool.submit(() -> runConnection(client));
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void runConnection(SSLSocket client) {
        try {
            InputStream input = client.getInputStream();
            BufferedReader req = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));

            String msg;
            while((msg = req.readLine()) != null) {
                SyslogMessage log = SyslogMessage.createFromString(msg);
                writeLog(log);

                String response = "OK\r\n";
                OutputStream out = client.getOutputStream();
                out.write(response.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeLog(SyslogMessage log) {
        File dir = new File("logs");

        if (!dir.exists()) {
            dir.mkdirs();
        }

        File logFile = new File(dir, log.getApplicationName() + ".log");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFile, true))) {
            writer.write(log.getFormattedString());
            writer.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}