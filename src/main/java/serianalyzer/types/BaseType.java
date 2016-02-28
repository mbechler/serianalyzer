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
 * Created: 13.11.2015 by mbechler
 */
package serianalyzer.types;


import java.util.HashSet;
import java.util.Set;

import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class BaseType {

    private boolean tainted;
    private String hint;

    private Set<Type> alternativeTypes = new HashSet<>();


    /**
     * @param tainted
     * @param hint
     * 
     */
    public BaseType ( boolean tainted, String hint ) {
        this.tainted = tainted;
        this.hint = hint;
    }


    /**
     * @return the tainted
     */
    public boolean isTainted () {
        return this.tainted;
    }


    /**
     * 
     */
    public void taint () {
        this.tainted = true;
    }


    /**
     * {@inheritDoc}
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString () {
        return this.hint + ( this.tainted ? " <T>" : " <U>" ); //$NON-NLS-1$ //$NON-NLS-2$
    }


    /**
     * @param objectType
     */
    public void addAlternativeType ( Type objectType ) {
        this.alternativeTypes.add(objectType);
    }


    /**
     * @return the alternativeTypes
     */
    public Set<Type> getAlternativeTypes () {
        return this.alternativeTypes;
    }
}
