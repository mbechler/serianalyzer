/**
 * © 2016 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 13.03.2016 by mbechler
 */
package serianalyzer;


/**
 * @author mbechler
 *
 */
public enum InitialSetType {

    /**
     * Includes the entry points that may be triggered by deserialization
     */
    JAVA,

    /**
     * JAVA + bean getter methods
     */
    GETTERS,

    /**
     * JAVA + zero argument methods
     */
    ZEROARGMETHOD,

    /**
     * JAVA + zero argument constructor
     */
    DEFAULTCONST,

    /**
     * JAVA + one argument string constructor
     */
    STRINGCONST
}
