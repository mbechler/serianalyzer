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

    private Set<Object> alternatives;


    /**
     * @param v
     */
    public MultiAlternatives ( Set<Object> v ) {
        super(anyTainted(v), "alternatives [ " + v + " ]"); //$NON-NLS-1$ //$NON-NLS-2$

        for ( Object alt : v ) {
            if ( alt instanceof MultiAlternatives ) {
                throw new IllegalArgumentException("Recursion"); //$NON-NLS-1$
            }
        }

        this.alternatives = v;
    }


    /**
     * @return the alternatives
     */
    public Set<Object> getAlternatives () {
        return this.alternatives;
    }


    /**
     * 
     * @return a common type for the alternatives
     */
    public Type getCommonType () {
        Type common = null;
        for ( Object object : this.getAlternatives() ) {

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
    private static boolean anyTainted ( Set<Object> v ) {
        for ( Object o : v ) {
            if ( o instanceof BaseType ) {
                if ( ( (BaseType) o ).isTainted() ) {
                    return true;
                }
            }
            else {
                return true;
            }
        }

        return false;
    }

}
