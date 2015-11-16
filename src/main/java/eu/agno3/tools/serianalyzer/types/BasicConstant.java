/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 12.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.types;


import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class BasicConstant extends BaseType implements SimpleType {

    private Type type;
    private Object value;


    /**
     * @param byteType
     * @param value
     */
    public BasicConstant ( Type byteType, Object value ) {
        super(false, "Constant " + value + " type " + byteType); //$NON-NLS-1$ //$NON-NLS-2$
        this.type = byteType;
        this.value = value;
    }


    /**
     * 
     * @param byteType
     * @param value
     * @param tainted
     */
    public BasicConstant ( Type byteType, Object value, boolean tainted ) {
        super(tainted, "Constant " + value); //$NON-NLS-1$
        this.type = byteType;
    }


    /**
     * @return the type
     */
    @Override
    public Type getType () {
        return this.type;
    }


    /**
     * @return the value
     */
    public Object getValue () {
        return this.value;
    }

}
