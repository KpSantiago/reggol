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

                        ConnectionContext ctx = new ConnectionContext(engine);

                        System.out.println("[INFO] Handshake is beginning");
                        ctx.engine.beginHandshake();

                        var ops = SelectionKey.OP_READ;

                        if (ctx.engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                            ops = SelectionKey.OP_WRITE;
                        }

                        clientChannel.register(selector, ops, ctx);
                    }

                    if (key.isReadable() || key.isWritable()) {
                        ConnectionContext ctx = (ConnectionContext) key.attachment();
                        SSLEngine engine = ctx.engine;

                        if (!ctx.handshakeDone) {
                            SecureSocketConfig.doHandshake(key);
                            SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
                            if (hs == SSLEngineResult.HandshakeStatus.FINISHED || hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING)
                                ctx.handshakeDone = true;
                        }

                        if (ctx.handshakeDone) {
                            System.out.println("[INFO] Handshake completed with success");
                            SocketChannel clientChannel = (SocketChannel) key.channel();

                            ctx.peerNetData.clear();
                            int n = clientChannel.read(ctx.peerNetData);

                            if (n < 0) {
                                ctx = null;
                                clientChannel.close();
                                key.cancel();
                                return;
                            }

                            if (n == 0) {
                                continue;
                            }

                            ctx.peerNetData.flip();
                            var res = engine.unwrap(ctx.peerNetData, ctx.peerAppData);
                            ctx.peerNetData.compact();

                            if (ctx.peerAppData.hasRemaining() && res.getStatus() == SSLEngineResult.Status.OK) {
                                var temp = new ByteArrayInputStream(ctx.peerAppData.array());
                                var result = new BufferedReader(new InputStreamReader(temp, StandardCharsets.UTF_8));
                                SyslogMessage msg = SyslogMessage.createFromString(result.readLine());

                                writeLog(msg);

                                String response = "OK/n";
                                ctx.myAppData = ByteBuffer.wrap(response.getBytes());
                                ctx.myAppData.flip();
                                clientChannel.write(ctx.myAppData);
                                ctx.myAppData.compact();

                                ctx = null;
                                clientChannel.close();
                                key.cancel();

                                System.out.println("[INFO] Connection closed with a success operation\n==================");
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