/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.tests;


import java.lang.reflect.Method;
import java.rmi.registry.Registry;
import java.util.HashSet;
import java.util.Set;

import sun.rmi.server.Util;


/**
 * @author mbechler
 *
 */
public class FindHashes {

    /**
     * @param args
     */
    public static void main ( String[] args ) {
        Set<Long> targets = new HashSet<>();
        for ( Method m : Registry.class.getDeclaredMethods() ) {
            long computeMethodHash = Util.computeMethodHash(m);
            System.out.println(m + " hash is " + computeMethodHash); //$NON-NLS-1$
            targets.add(computeMethodHash);
        }
    }

}
