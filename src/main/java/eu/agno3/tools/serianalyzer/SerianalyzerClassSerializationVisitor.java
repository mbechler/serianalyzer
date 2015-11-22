/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 11.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import org.apache.log4j.Logger;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;


/**
 * @author mbechler
 *
 */
public class SerianalyzerClassSerializationVisitor extends ClassVisitor implements SerianalyzerClassVisitorBase {

    private static final Logger log = Logger.getLogger(SerianalyzerClassSerializationVisitor.class);

    private String clName;
    private Serianalyzer analyzer;
    private boolean serializable;

    private boolean foundDefaultConstructor;


    /**
     * @param analyzer
     * @param clName
     * @param serializable
     * 
     */
    public SerianalyzerClassSerializationVisitor ( Serianalyzer analyzer, String clName, boolean serializable ) {
        super(Opcodes.ASM5);
        this.analyzer = analyzer;
        this.clName = clName;
        this.serializable = serializable;
    }


    /**
     * @return the analyzer
     */
    @Override
    public Serianalyzer getAnalyzer () {
        return this.analyzer;
    }


    /**
     * @return the clName
     */
    @Override
    public String getClassName () {
        return this.clName;
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.ClassVisitor#visitAttribute(org.objectweb.asm.Attribute)
     */
    @Override
    public void visitAttribute ( Attribute attr ) {
        log.debug("Found attribute " + attr); //$NON-NLS-1$
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.ClassVisitor#visitMethod(int, java.lang.String, java.lang.String, java.lang.String,
     *      java.lang.String[])
     */
    @Override
    public MethodVisitor visitMethod ( int access, String name, String desc, String signature, String[] exceptions ) {

        if ( isReachableMethod(name, desc, access) ) {
            if ( log.isTraceEnabled() ) {
                log.trace(String.format("Found %s::%s with signature %s", this.clName, name, desc)); //$NON-NLS-1$ 
            }

            this.foundDefaultConstructor = isDefaultConstructor(name, desc, access);
            MethodReference ref = new MethodReference(this.clName, false, name, false, desc);
            if ( this.analyzer.getConfig().isWhitelisted(ref) ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Whitelisted " + ref); //$NON-NLS-1$
                }
                return super.visitMethod(access, name, desc, signature, exceptions);
            }
            ref.taintCallee();
            taintArguments(ref, name, desc, access);
            this.getAnalyzer().getState().addInitial(ref);

            return new SerianalyzerMethodVisitor(this, ref);
        }

        return super.visitMethod(access, name, desc, signature, exceptions);
    }


    /**
     * @param ref
     * @param name
     * @param signature
     * @param access
     */
    private static void taintArguments ( MethodReference ref, String name, String signature, int access ) {
        if ( "readObject".equals(name) && "(Ljava/io/ObjectInputStream;)V".equals(signature) ) { //$NON-NLS-1$ //$NON-NLS-2$
            ref.taintParameterReturns(0);
        }
        else if ( "readExternal".equals(name) && "(Ljava/io/ObjectInput;)V".equals(signature) ) { //$NON-NLS-1$//$NON-NLS-2$
            ref.taintParameterReturns(0);
        }
        else if ( "invoke".equals(name) && "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;".equals(signature) ) { //$NON-NLS-1$ //$NON-NLS-2$
            ref.taintParameter(0);
            ref.taintParameter(1);
            ref.taintParameter(2);
        }
    }


    /**
     * @return the foundDefaultConstructor
     */
    public boolean isFoundDefaultConstructor () {
        return this.foundDefaultConstructor;
    }


    /**
     * @param name
     * @param signature
     * @return
     */
    private boolean isReachableMethod ( String name, String signature, int access ) {
        return ( this.serializable && "readObject".equals(name) && "(Ljava/io/ObjectInputStream;)V".equals(signature) ) || //$NON-NLS-1$ //$NON-NLS-2$
                ( this.serializable && "readExternal".equals(name) && "(Ljava/io/ObjectInput;)V".equals(signature) ) || //$NON-NLS-1$ //$NON-NLS-2$
                ( this.serializable && "readObjectNoData".equals(name) && "()V".equals(signature) ) || //$NON-NLS-1$ //$NON-NLS-2$
                ( this.serializable && "invoke".equals(name) && "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;" //$NON-NLS-1$ //$NON-NLS-2$
                .equals(signature) ) || isDefaultConstructor(name, signature, access);
    }


    /**
     * @param name
     * @param signature
     * @param access
     * @return
     */
    private boolean isDefaultConstructor ( String name, String signature, int access ) {
        return !this.serializable && "<init>".equals(name) && "()V".equals(signature) && ( access & Opcodes.ACC_PUBLIC ) != 0; //$NON-NLS-1$ //$NON-NLS-2$
    }
}
