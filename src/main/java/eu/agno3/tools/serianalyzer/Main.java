/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 11.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;


/**
 * @author mbechler
 *
 */
public class Main {

    private static final Logger log = Logger.getLogger(Main.class);


    /**
     * @param args
     */
    public static void main ( String[] args ) {

        List<String> remainArgs = new ArrayList<>();
        SerianalyzerConfig config = configure(args, remainArgs);
        final SerianalyzerInput input = new SerianalyzerInput(config);

        if ( remainArgs.isEmpty() ) {
            System.err.println("Usage: serianalyzer [-w|--whitelist <whitelist>] [-i|-o <file>] [-n] [-d] <jar file/directory...>"); //$NON-NLS-1$
            System.err.println("    -w      Whitelist file"); //$NON-NLS-1$
            System.err.println("    -n      Disable heuristics"); //$NON-NLS-1$
            System.err.println("    -d      Dump instantiation details"); //$NON-NLS-1$
            System.err.println("    -i      Read analyzed state (do not run on untrusted inputs ;))"); //$NON-NLS-1$
            System.err.println("    -o      Write analyzed state (do not run on untrusted inputs ;))"); //$NON-NLS-1$
            System.err.println();
            System.exit(-1);
        }

        try {
            for ( String arg : remainArgs ) {
                log.info("Indexing " + arg); //$NON-NLS-1$
                input.index(Paths.get(arg));
            }
        }
        catch ( IOException e ) {
            log.error(e);
        }

        log.info("Indexing complete"); //$NON-NLS-1$

        Serianalyzer analyzer = new Serianalyzer(input);
        try {
            analyzer.analyze();
        }
        catch ( SerianalyzerException e ) {
            log.error("Failed to perform analysis", e); //$NON-NLS-1$
        }

    }


    /**
     * @param args
     * @param remainArgs
     * @return
     */
    private static SerianalyzerConfig configure ( String[] args, List<String> remainArgs ) {

        String whitelistArg = null;
        boolean noHeuristics = false;
        boolean dumpInstantiation = false;
        File saveFile = null;
        File restoreFile = null;

        int i = 0;
        for ( ; i < args.length; i++ ) {
            String arg = args[ i ];
            if ( "-w".equals(arg) || "--whitelist".equals(arg) ) { //$NON-NLS-1$ //$NON-NLS-2$
                i++;
                whitelistArg = args[ i ];
            }
            else if ( "-n".equals(arg) || "--noheuristic".equals(arg) ) { //$NON-NLS-1$//$NON-NLS-2$
                noHeuristics = true;
            }
            else if ( "-d".equals(arg) || "--dumpinstantiation".equals(arg) ) { //$NON-NLS-1$//$NON-NLS-2$
                dumpInstantiation = true;
            }
            else if ( "-i".equals(arg) || "--input".equals(arg) ) { //$NON-NLS-1$ //$NON-NLS-2$
                i++;
                restoreFile = new File(args[ i ]);
            }
            else if ( "-o".equals(arg) || "--output".equals(arg) ) { //$NON-NLS-1$ //$NON-NLS-2$
                i++;
                saveFile = new File(args[ i ]);
            }
            else {
                break;
            }
        }

        SerianalyzerConfig config = new SerianalyzerConfig(noHeuristics, dumpInstantiation);
        if ( whitelistArg != null ) {
            try ( FileInputStream fis = new FileInputStream(whitelistArg) ) {
                config.readFile(fis);
            }
            catch ( IOException e ) {
                System.exit(-1);
            }
        }

        config.setSaveTo(saveFile);
        config.setRestoreFrom(restoreFile);

        for ( ; i < args.length; i++ ) {
            remainArgs.add(args[ i ]);
        }
        return config;
    }
}
