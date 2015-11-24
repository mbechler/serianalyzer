/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 12.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.types;


import java.util.Set;

import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class MultiAlternatives extends BaseType {

    private Set<BaseType> alternatives;


    /**
     * @param v
     */
    public MultiAlternatives ( Set<BaseType> v ) {
        super(anyTainted(v), "alternatives [ " + v + " ]"); //$NON-NLS-1$ //$NON-NLS-2$

        for ( BaseType alt : v ) {
            if ( alt instanceof MultiAlternatives ) {
                throw new IllegalArgumentException("Recursion"); //$NON-NLS-1$
            }
        }

        this.alternatives = v;
    }


    /**
     * @return the alternatives
     */
    public Set<BaseType> getAlternatives () {
        return this.alternatives;
    }


    /**
     * 
     * @return a common type for the alternatives
     */
    public Type getCommonType () {
        Type common = null;
        for ( BaseType object : this.getAlternatives() ) {

            if ( object == null ) {
                return Type.VOID_TYPE;
            }

            Type t = null;
            if ( object instanceof SimpleType ) {
                t = ( (SimpleType) object ).getType();
            }

            if ( t != null && ( common == null || common.equals(t) ) ) {
                common = t;
                continue;
            }

            return Type.VOID_TYPE;

        }

        return common;
    }


    /**
     * @param v
     * @return
     */
    private static boolean anyTainted ( Set<BaseType> v ) {
        for ( BaseType o : v ) {
            if ( o == null ) {
                return true;
            }
            if ( o.isTainted() ) {
                return true;
            }
        }

        return false;
    }

}
