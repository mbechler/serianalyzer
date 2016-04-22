package serianalyzer;

import org.apache.log4j.Logger;

public class Verbose {
	
	public static boolean VERBOSE = false;
	
	private static Logger log = Logger.getLogger( Verbose.class );
	
	public static void println( String line ) { 
		log.info( line );
		
		if ( VERBOSE ) { 
			System.err.println( line );
		}
	}

}
