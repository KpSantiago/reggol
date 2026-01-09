package me.kpsantiago.reggol.config;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;

public class ConnectionContext {
    public final SSLEngine engine;
    public ByteBuffer peerNetData;
    public ByteBuffer peerAppData;
    public ByteBuffer myAppData;
    public ByteBuffer myNetData;
    public boolean handshakeDone;

    public ConnectionContext(SSLEngine engine) {
        this.engine = engine;
        SSLSession session = engine.getSession();
        this.myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        this.peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        this.peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        this.myAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        this.handshakeDone = false;
    }
}
