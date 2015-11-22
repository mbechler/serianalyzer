/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 12.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.util.Comparator;


/**
 * @author mbechler
 *
 */
public class MethodReferenceComparator implements Comparator<MethodReference> {

    /**
     * {@inheritDoc}
     *
     * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
     */
    @Override
    public int compare ( MethodReference o1, MethodReference o2 ) {
        int res = o1.getTypeNameString().compareTo(o2.getTypeNameString());
        if ( res != 0 ) {
            return res;
        }
        return o1.getMethod().compareTo(o2.getMethod());
    }

}
