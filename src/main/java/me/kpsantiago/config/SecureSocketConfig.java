package me.kpsantiago.config;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
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

        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();

        switch (hs) {
            case NEED_UNWRAP: {
                int n = channel.read(ctx.peerNetData);
                if (n < 0) {
                    engine.closeOutbound();
                    channel.close();
                    key.cancel();
                    return;
                }

                if (n == 0) {
                    key.interestOps(SelectionKey.OP_READ);
                    return;
                }

                ctx.peerNetData.flip();
                SSLEngineResult res = engine.unwrap(ctx.peerNetData, ctx.peerAppData);
                ctx.peerNetData.compact();
//                hs = res.getHandshakeStatus();

                handleKeyOperation(key, engine, res);

                switch (res.getStatus()) {
                    case OK:
                        break;
                    case BUFFER_OVERFLOW:
                        ctx.peerAppData = enlargeBuffer(ctx.peerAppData, engine.getSession().getApplicationBufferSize());
                        break;
                    case BUFFER_UNDERFLOW:
                        int needed = engine.getSession().getPacketBufferSize();
                        if (ctx.peerNetData.capacity() < needed) {
                            ctx.peerNetData = enlargeBuffer(ctx.peerNetData, needed);
                        }
                        return;
                    case CLOSED:
                        System.out.println("[INFO] Handshake closed: connection closed.");
                        engine.closeOutbound();
                        channel.close();
                        key.cancel();
                        break;
                }
                break;
            }

            case NEED_WRAP: {
                ctx.myNetData.clear();
                SSLEngineResult res = engine.wrap(ctx.myAppData, ctx.myNetData);
//                hs = res.getHandshakeStatus();

                handleKeyOperation(key, engine, res);

                switch (res.getStatus()) {
                    case OK:
                        ctx.myNetData.flip();
                        channel.write(ctx.myNetData);

                        if (ctx.myNetData.hasRemaining()) {
                            key.interestOps(SelectionKey.OP_WRITE);
                        }

                        break;
                    case BUFFER_OVERFLOW:
                        ctx.myNetData = enlargeBuffer(ctx.myNetData, engine.getSession().getPacketBufferSize());
                        break;
                    case CLOSED:
                        System.out.println("[INFO] Handshake closed: connection closed.");
                        engine.closeOutbound();
                        channel.close();
                        key.cancel();
                        break;
                }
                break;
            }
            case NEED_UNWRAP_AGAIN: {
                ctx.peerNetData.flip();
                SSLEngineResult res = engine.unwrap(ctx.peerNetData, ctx.peerAppData);
                ctx.peerNetData.compact();
//                hs = res.getHandshakeStatus();

                handleKeyOperation(key, engine, res);

                switch (res.getStatus()) {
                    case OK:
                        break;
                    case BUFFER_OVERFLOW:
                        ctx.peerAppData = enlargeBuffer(ctx.peerAppData, engine.getSession().getApplicationBufferSize());
                        break;
                    case BUFFER_UNDERFLOW:
                        int needed = engine.getSession().getPacketBufferSize();
                        if (ctx.peerNetData.capacity() < needed) {
                            ctx.peerNetData = enlargeBuffer(ctx.peerNetData, needed);
                        }
                        return;
                    case CLOSED:
                        System.out.println("[INFO] Handshake closed: connection closed.");
                        engine.closeOutbound();
                        key.cancel();
                        channel.close();
                        break;
                }
                break;
            }
            case NOT_HANDSHAKING:
            case FINISHED:
                key.interestOps(SelectionKey.OP_READ);
                break;
        }
    }

    private static void handleKeyOperation(SelectionKey key, SSLEngine engine, SSLEngineResult res) {
        switch (res.getHandshakeStatus()) {
            case NEED_UNWRAP,
                 NEED_UNWRAP_AGAIN,
                 FINISHED,
                 NOT_HANDSHAKING:
                key.interestOps(SelectionKey.OP_READ);
                break;
            case NEED_WRAP:
                key.interestOps(SelectionKey.OP_WRITE);
                break;
            case NEED_TASK:
                Runnable task;
                while ((task = engine.getDelegatedTask()) != null) {
                    task.run();
                }
                var hs = engine.getHandshakeStatus();
                if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    key.interestOps(SelectionKey.OP_WRITE);
                } else if (hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    key.interestOps(SelectionKey.OP_READ);
                }
                break;
        }
    }


    private static ByteBuffer enlargeBuffer(ByteBuffer buffer, int newCapacity) {
        ByteBuffer newBuffer = ByteBuffer.allocate(newCapacity);
        buffer.flip();
        newBuffer.put(buffer);
        return newBuffer;
    }
}
