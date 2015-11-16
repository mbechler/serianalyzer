/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 11.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


/**
 * @author mbechler
 *
 */
public class SerianalyzerException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = -4093981858131960024L;


    /**
     * 
     */
    public SerianalyzerException () {}


    /**
     * @param message
     */
    public SerianalyzerException ( String message ) {
        super(message);
    }


    /**
     * @param cause
     */
    public SerianalyzerException ( Throwable cause ) {
        super(cause);
    }


    /**
     * @param message
     * @param cause
     */
    public SerianalyzerException ( String message, Throwable cause ) {
        super(message, cause);
    }


    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public SerianalyzerException ( String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace ) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
