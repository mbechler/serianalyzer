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
public class BasicVariable extends BaseType implements SimpleType {

    private Type type;
    private boolean taintReturns;


    /**
     * @param intType
     * @param hint
     * @param tainted
     * @param taintReturns
     */
    public BasicVariable ( Type intType, String hint, boolean tainted, boolean taintReturns ) {
        super(tainted, hint);
        this.type = intType;
        this.taintReturns = taintReturns;
    }


    /**
     * @param intType
     * @param hint
     * @param tainted
     */
    public BasicVariable ( Type intType, String hint, boolean tainted ) {
        this(intType, hint, tainted, false);
    }


    /**
     * @return the taintReturns
     */
    public boolean isTaintReturns () {
        return this.taintReturns;
    }


    /**
     * @return the variable type
     */
    @Override
    public Type getType () {
        return this.type;
    }

}
