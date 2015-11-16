/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 11.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import org.jboss.jandex.DotName;


/**
 * @author mbechler
 *
 */
public interface SerianalyzerClassVisitorBase {

    /**
     * @return the analyzer
     */
    Serianalyzer getAnalyzer ();


    /**
     * @return the target class name
     */
    DotName getClassName ();

}
