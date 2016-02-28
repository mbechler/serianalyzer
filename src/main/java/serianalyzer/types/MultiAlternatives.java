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
package serianalyzer.types;


import java.util.Set;

import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class MultiAlternatives extends BaseType {

    private Set<BaseType> alternatives;


    /**
     * @param v
     */
    public MultiAlternatives ( Set<BaseType> v ) {
        super(anyTainted(v), "alternatives [ " + v + " ]"); //$NON-NLS-1$ //$NON-NLS-2$

        for ( BaseType alt : v ) {
            if ( alt instanceof MultiAlternatives ) {
                throw new IllegalArgumentException("Recursion"); //$NON-NLS-1$
            }
        }

        this.alternatives = v;
    }


    /**
     * @return the alternatives
     */
    public Set<BaseType> getAlternatives () {
        return this.alternatives;
    }


    /**
     * 
     * @return a common type for the alternatives
     */
    public Type getCommonType () {
        Type common = null;
        for ( BaseType object : this.getAlternatives() ) {

            if ( object == null ) {
                return Type.VOID_TYPE;
            }

            Type t = null;
            if ( object instanceof SimpleType ) {
                t = ( (SimpleType) object ).getType();
            }

            if ( t != null && ( common == null || common.equals(t) ) ) {
                common = t;
                continue;
            }

            return Type.VOID_TYPE;

        }

        return common;
    }


    /**
     * @param v
     * @return
     */
    private static boolean anyTainted ( Set<BaseType> v ) {
        for ( BaseType o : v ) {
            if ( o == null ) {
                return true;
            }
            if ( o.isTainted() ) {
                return true;
            }
        }

        return false;
    }

}
