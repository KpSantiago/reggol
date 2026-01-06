package me.kpsantiago.config;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;

public class SecureSocketConfig {
    public static SSLEngine config() throws Exception {
        char[] passphrase = "passphrase".toCharArray();

        // Key Material -> identify the server
        KeyStore ksKeys = KeyStore.getInstance("JKS");
        ksKeys.load(new FileInputStream("serverkeystore.jks"), passphrase);

        // Trust Material -> identify the ctx.peers
        KeyStore ksTrust = KeyStore.getInstance("JKS");
        ksTrust.load(new FileInputStream("servertruststore.jks"), passphrase);

        // KeyManagers decide which key material to use
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(ksKeys, passphrase);

        // Trust Manager Factory decides whether to allow connection
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ksTrust);

        // Initiate SSLContext to use TLS
        // Pass the key and trust material to context know how to authenticate
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        // Initiate SSLEngine
        SSLEngine engine = sslContext.createSSLEngine();
        engine.setNeedClientAuth(true);
        engine.setUseClientMode(false);

        // return ssl engine
        return engine;
    }

    public static void doHandshake(SelectionKey key) throws SSLException, IOException {
        SocketChannel channel = (SocketChannel) key.channel();
        ConnectionContext ctx = (ConnectionContext) key.attachment();
        SSLEngine engine = ctx.engine;
        
        engine.beginHandshake();
        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();

        while(hs != SSLEngineResult.HandshakeStatus.FINISHED && hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch (hs) {
                case NEED_UNWRAP: {
                    key.interestOps(SelectionKey.OP_READ);
                    if (channel.read(ctx.peerNetData) < 0) {
                        throw new RuntimeException("Connection closed prematurely");
                    }
                    ctx.peerNetData.flip();
                    SSLEngineResult res = engine.unwrap(ctx.peerNetData, ctx.peerAppData);
                    ctx.peerNetData.compact();
                    hs = res.getHandshakeStatus();

                    switch (res.getStatus()) {
                        case OK:
                            break;
                        case BUFFER_OVERFLOW:
                            ctx.peerAppData = enlargeBuffer(ctx.peerAppData, engine.getSession().getApplicationBufferSize());
                            break;
                        case BUFFER_UNDERFLOW:
                            ctx.peerNetData = enlargeBuffer(ctx.peerNetData, engine.getSession().getPacketBufferSize());
                            break;
                        case CLOSED:
                            System.out.println("[INFO] Handshake closed: connection closed.");
                            engine.closeOutbound();
                            channel.close();
                            break;
                    }
                }
                case NEED_WRAP: {
                    key.interestOps(SelectionKey.OP_WRITE);
                    ctx.myNetData.clear();
                    SSLEngineResult res = engine.wrap(ctx.myAppData, ctx.myNetData);
                    hs = res.getHandshakeStatus();

                    switch (res.getStatus()) {
                        case OK:
                            ctx.myNetData.flip();
                            while (ctx.myNetData.hasRemaining()) {
                                channel.write(ctx.myNetData);
                            }
                            break;
                        case BUFFER_OVERFLOW:
                            ctx.myNetData = enlargeBuffer(ctx.myNetData, engine.getSession().getPacketBufferSize());
                            break;
                        case BUFFER_UNDERFLOW:
                            throw new SSLException("Incorrect size for buffer.");
                        case CLOSED:
                            System.out.println("[INFO] Handshake closed: connection closed.");
                            engine.closeOutbound();
                            channel.close();
                            break;
                    }
                }
                case NEED_UNWRAP_AGAIN: {
                    key.interestOps(SelectionKey.OP_READ);
                    ctx.peerNetData.flip();
                    SSLEngineResult res = engine.unwrap(ctx.peerNetData, ctx.peerAppData);
                    ctx.peerNetData.compact();
                    hs = res.getHandshakeStatus();
                }
                case NEED_TASK: {
                    key.interestOps(SelectionKey.OP_READ);
                    Runnable task;
                    if ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    hs = engine.getHandshakeStatus();
                }
            }
        }
        key.interestOps(SelectionKey.OP_READ);
    }

    private static ByteBuffer enlargeBuffer(ByteBuffer buffer, int newCapacity) {
        ByteBuffer newBuffer = ByteBuffer.allocate(newCapacity);
        buffer.flip();
        newBuffer.put(buffer);
        return newBuffer;
    }
}
