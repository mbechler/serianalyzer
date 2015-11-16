/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 13.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.types;


import java.util.Set;

import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public interface SimpleType {

    /**
     * @return the type
     */
    Type getType ();


    /**
     * @return the alternativeTypes
     */
    Set<Type> getAlternativeTypes ();
}
