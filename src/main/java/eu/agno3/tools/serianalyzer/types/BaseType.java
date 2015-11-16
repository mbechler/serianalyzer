/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 13.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.types;


import java.util.HashSet;
import java.util.Set;

import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class BaseType {

    private boolean tainted;
    private String hint;

    private Set<Type> alternativeTypes = new HashSet<>();


    /**
     * @param tainted
     * @param hint
     * 
     */
    public BaseType ( boolean tainted, String hint ) {
        this.tainted = tainted;
        this.hint = hint;
    }


    /**
     * @return the tainted
     */
    public boolean isTainted () {
        return this.tainted;
    }


    /**
     * 
     */
    public void taint () {
        this.tainted = true;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        return this.hint + ( this.tainted ? " <T>" : " <U>" ); //$NON-NLS-1$ //$NON-NLS-2$
    }


    /**
     * @param objectType
     */
    public void addAlternativeType ( Type objectType ) {
        this.alternativeTypes.add(objectType);
    }


    /**
     * @return the alternativeTypes
     */
    public Set<Type> getAlternativeTypes () {
        return this.alternativeTypes;
    }
}
