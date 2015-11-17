/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


/**
 * @author mbechler
 *
 */
public enum RemovalReason {

    /**
     * Whitelisted
     */
    WHITELIST,

    /**
     * No callers remain
     */
    NOCALLERS,

    /**
     * Type not instantiable
     */
    UNINSTATIABLE,

    /**
     * No callees left
     */
    NOCALLEES,

}
