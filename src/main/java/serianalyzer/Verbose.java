package serianalyzer;


import org.apache.log4j.Logger;


/**
 * @author drosenbauer
 *
 */
public class Verbose {

    /**
     * Whether to display verbose output
     */
    public static boolean VERBOSE = false;

    /**
     * Whether to produce logger output per class/method
     */
    public static boolean PER_INSTANCE_LOG = false;

    private static Logger log = Logger.getLogger(Verbose.class);

    private static final StringBuilder SB = new StringBuilder();


    /**
     * @param line
     */
    public static void println ( String line ) {
        log.info(line);

        if ( VERBOSE ) {
            System.err.println(line);
        }
    }


    /**
     * Totally not thread-safe
     * 
     * @param methodReference
     * @return a logger for the method reference
     */
    public static Logger getPerMethodLogger ( MethodReference methodReference ) {
        if ( !PER_INSTANCE_LOG ) {
            return log;
        }
        SB.setLength(0);
        SB.append(Serianalyzer.class.getName()).append('.');
        SB.append(methodReference.getTypeNameString()).append('.');
        SB.append(methodReference.getMethod());
        return Logger.getLogger(SB.toString());
    }


    /**
     * Totally not thread-safe
     * 
     * @param typeName
     * @return a logger for the given type
     */
    public static Logger getPerClassLogger ( String typeName ) {
        if ( !PER_INSTANCE_LOG ) {
            return log;
        }
        SB.setLength(0);
        SB.append(Serianalyzer.class.getName()).append('.');
        SB.append(typeName);
        return Logger.getLogger(SB.toString());
    }

}
