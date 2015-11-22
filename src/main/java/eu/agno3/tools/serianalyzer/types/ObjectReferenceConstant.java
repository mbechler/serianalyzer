/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 13.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.types;


import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class ObjectReferenceConstant extends BaseType implements SimpleType {

    private String clazz;
    private Type t;


    /**
     * @param tainted
     * @param t
     * @param clazz
     */
    public ObjectReferenceConstant ( boolean tainted, Type t, String clazz ) {
        super(tainted, "Objref " + clazz); //$NON-NLS-1$
        this.t = t;
        this.clazz = clazz;
    }


    /**
     * @return the clazz
     */
    public String getClassName () {
        return this.clazz;
    }


    /**
     * @return the t
     */
    @Override
    public Type getType () {
        return this.t;
    }

}
