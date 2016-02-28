/**
 *   This file is part of Serianalyzer.
 *
 *   Serianalyzer is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Serianalyzer is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Serianalyzer.  If not, see <http://www.gnu.org/licenses/>.
 *   
 * Copyright 2015,2016 Moritz Bechler <mbechler@eenterphace.org>
 * 
 * Created: 12.11.2015 by mbechler
 */
package serianalyzer;


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
