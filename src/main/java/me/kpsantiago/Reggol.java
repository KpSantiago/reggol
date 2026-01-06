package me.kpsantiago;

import me.kpsantiago.config.ConnectionContext;
import me.kpsantiago.config.SecureSocketConfig;
import me.kpsantiago.syslog.SyslogMessage;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Set;

public class Reggol {
    public static void main(String[] args) {
        try (
                ServerSocketChannel serverChannel = ServerSocketChannel.open();
                Selector selector = Selector.open()
        ) {
            serverChannel.configureBlocking(false);
            serverChannel.bind(new InetSocketAddress("127.0.0.1", 888));
            serverChannel.register(selector, SelectionKey.OP_ACCEPT);

            while (true) {
                selector.select();
                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> it = keys.iterator();

                while (it.hasNext()) {
                    SelectionKey key = it.next();
                    it.remove();

                    if (key.isAcceptable()) {
                        SocketChannel clientChannel = serverChannel.accept();
                        clientChannel.configureBlocking(false);

                        SSLEngine engine = SecureSocketConfig.config();
                        engine.beginHandshake();

                        ConnectionContext ctx = new ConnectionContext(engine);

                        // registra o cliente para leitura
                        clientChannel.register(selector, SelectionKey.OP_WRITE, ctx);
                    }

                    if(key.isReadable()) {
                        // fazer handshake
                        SecureSocketConfig.doHandshake(key);

                        SocketChannel clientChannel = (SocketChannel) key.channel();
                        ConnectionContext ctx = (ConnectionContext) key.attachment();
                        SSLEngine engine = ctx.engine;
                        SSLSession session = engine.getSession();

                        int n = clientChannel.read(ctx.peerNetData);

                        if (n == -1) {

                        } else if (n == 0) {

                        } else {
                            ctx.peerNetData.flip();
                            var res = engine.unwrap(ctx.peerNetData, ctx.peerAppData);

                            if (res.getStatus() == SSLEngineResult.Status.OK) {
                                ctx.peerNetData.compact();

                                if (ctx.peerAppData.hasRemaining()) {
                                    var temp = new ByteArrayInputStream(ctx.peerAppData.array());
                                    var result = new BufferedReader(new InputStreamReader(temp, StandardCharsets.UTF_8));
                                    SyslogMessage msg = SyslogMessage.createFromString(result.readLine());
                                    writeLog(msg);
                                }
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
//        while (true) {
//            try (SSLServerSocket serverSocket = (SSLServerSocket) SecureSocketConfig.config().createServerSocket(888, 50, InetAddress.getByName("127.0.0.1"))) {
//                serverSocket.setNeedClientAuth(true);
//
//                SSLSocket client = (SSLSocket) serverSocket.accept();
//                var result = new BufferedReader(new InputStreamReader(client.getInputStream()));
//                SyslogMessage msg = SyslogMessage.createFromString(result.readLine());
//                writeLog(msg);
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//        }
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