/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 16.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.tests;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.ArrayList;
import java.util.List;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;


/**
 * @author mbechler
 *
 */
public class Tests {

    // A - create an insane amount of system threads
    private static void testLiveREFs () throws ClassNotFoundException, IOException {
        ObjID id = new ObjID(1234);
        List<Object> refs = new ArrayList<>();

        for ( int i = 0; i < 100000; i++ ) {
            TCPEndpoint te = new TCPEndpoint("127.0.0.1", i); //$NON-NLS-1$
            refs.add(new UnicastRef(new LiveRef(id, te, false)));
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(refs);
        try ( ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray())) ) {
            ois.readObject();
        }

    }


    // B - connect to the given TCP endpoint,

    private static void testProxyREF () throws ClassNotFoundException, IOException {
        ObjID id = new ObjID(1234);
        TCPEndpoint te = new TCPEndpoint("127.0.0.1", 12344); //$NON-NLS-1$
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObject obj = new RemoteObjectInvocationHandler(ref);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        try ( ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray())) ) {
            ois.readObject();
        }

    }


    /**
     * @param args
     */
    public static void main ( String[] args ) {

        try {
            testProxyREF();

            testLiveREFs();
        }
        catch (
            ClassNotFoundException |
            IOException e ) {
            e.printStackTrace();
        }
    }
}
