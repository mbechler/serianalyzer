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
     * bean getter methods
     */
    GETTERS,

    /**
     * bean setter methods
     */
    SETTERS,

    /**
     * zero argument methods
     */
    ZEROARGMETHOD,

    /**
     * zero argument constructor
     */
    DEFAULTCONST,

    /**
     * one argument string constructor
     */
    STRINGCONST,

    /**
     * all constructors
     */
    ALLCONST,

    /**
     * Finalizers
     */
    FINALIZE,

    /**
     * Methods commonly called (toString(),hashCode(),equals(Object),java.lang.Comparable->compareTo(Object))
     */
    COMMON,

    /**
     * Castor extra methods addXXX/createXXX
     */
    CASTOR,

    /**
     * Proxy invocation handler
     */
    PROXY,

    /**
     * readReplace invocation
     */
    READ_RESOLVE
}
