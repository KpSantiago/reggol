package me.kpsantiago.reggol;

import me.kpsantiago.reggol.config.SecureSocketConfig;
import me.kpsantiago.reggol.models.ClientCredentials;
import me.kpsantiago.reggol.syslog.SyslogMessage;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.PasswordGenerator;

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
            while ((msg = req.readLine()) != null) {
                SyslogMessage log = SyslogMessage.createFromString(msg);
                ClientCredentials c = writeLog(log);

                String response = "[INFO] Log received with success\r\n";
                if (c != null) {
                    response = String.format("[INFO] Client credentials: {\"application\":\"%s\",\"password\":\"%s\"}\r\n", c.getApplication(), c.getPassword());
                }
                OutputStream out = client.getOutputStream();
                out.write(response.getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static ClientCredentials writeLog(SyslogMessage log) {
        File dir = new File("logs");

        if (!dir.exists()) {
            dir.mkdirs();
        }

        String pass = generateClientPassword();
        String app = log.getHostname() + "_" +log.getApplicationName();

        File logFile = new File(dir, app + ".log");

        boolean isFirstLog = false;
        if (!logFile.exists()) {
            isFirstLog = true;
        }
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFile, true))) {
            writer.write(log.getFormattedString());
            writer.newLine();
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (isFirstLog) {
            return new ClientCredentials(app, pass);
        }

        return null;
    }

    private static String generateClientPassword() {
        PasswordGenerator gen = new PasswordGenerator();
        CharacterRule lowerCaseRule = new CharacterRule(EnglishCharacterData.LowerCase, 2);
        CharacterRule upperCaseRule = new CharacterRule(EnglishCharacterData.UpperCase, 2);
        CharacterRule digitRule = new CharacterRule(EnglishCharacterData.Digit, 2);

        return gen.generatePassword(16, lowerCaseRule, upperCaseRule, digitRule);
    }
}