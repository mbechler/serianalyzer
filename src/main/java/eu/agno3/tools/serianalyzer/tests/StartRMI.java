/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 17.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer.tests;


import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;


/**
 * @author mbechler
 *
 */
public class StartRMI {

    /**
     * @param args
     */
    public static void main ( String[] args ) {

        try {
            LocateRegistry.createRegistry(12344);
        }
        catch ( RemoteException e ) {
            e.printStackTrace();
            return;
        }

        while ( true ) {
            try {
                Thread.sleep(1);
            }
            catch ( InterruptedException e ) {
                break;
            }
        }
    }

}
