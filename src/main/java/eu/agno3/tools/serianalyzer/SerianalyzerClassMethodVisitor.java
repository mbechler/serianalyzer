/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 11.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import org.apache.log4j.Logger;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;


/**
 * @author mbechler
 *
 */
public class SerianalyzerClassMethodVisitor extends ClassVisitor implements SerianalyzerClassVisitorBase {

    private static final Logger log = Logger.getLogger(SerianalyzerClassMethodVisitor.class);

    private String clName;
    private Serianalyzer analyzer;

    private MethodReference ref;

    private boolean found;


    /**
     * @param analyzer
     * @param ref
     * @param clName
     * 
     */
    public SerianalyzerClassMethodVisitor ( Serianalyzer analyzer, MethodReference ref, String clName ) {
        super(Opcodes.ASM5);
        this.analyzer = analyzer;
        this.ref = ref;
        if ( log.isTraceEnabled() ) {
            log.trace("Trying to find " + ref); //$NON-NLS-1$
        }
        this.clName = clName;
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
     * @see org.objectweb.asm.ClassVisitor#visitMethod(int, java.lang.String, java.lang.String, java.lang.String,
     *      java.lang.String[])
     */
    @Override
    public MethodVisitor visitMethod ( int access, String name, String desc, String signature, String[] exceptions ) {
        if ( log.isTraceEnabled() ) {
            log.trace(String.format("Found %s::%s with signature %s", this.clName, name, desc)); //$NON-NLS-1$ 
        }

        if ( this.ref.getMethod().equals(name) && this.ref.getSignature().equals(desc) ) {
            this.found = true;
            if ( ( access & Opcodes.ACC_NATIVE ) != 0 ) {
                this.analyzer.getState().nativeCall(this.ref);
            }
            return new SerianalyzerMethodVisitor(this, this.ref);
        }

        return super.visitMethod(access, name, desc, signature, exceptions);
    }


    /**
     * @return the found
     */
    public boolean isFound () {
        return this.found;
    }
}
