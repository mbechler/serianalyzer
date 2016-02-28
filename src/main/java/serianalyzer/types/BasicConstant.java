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


import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class BasicConstant extends BaseType implements SimpleType {

    private Type type;
    private Object value;


    /**
     * @param byteType
     * @param value
     */
    public BasicConstant ( Type byteType, Object value ) {
        super(false, "Constant " + value + " type " + byteType); //$NON-NLS-1$ //$NON-NLS-2$
        this.type = byteType;
        this.value = value;
    }


    /**
     * 
     * @param byteType
     * @param value
     * @param tainted
     */
    public BasicConstant ( Type byteType, Object value, boolean tainted ) {
        super(tainted, "Constant " + value); //$NON-NLS-1$
        this.type = byteType;
    }


    /**
     * @return the type
     */
    @Override
    public Type getType () {
        return this.type;
    }


    /**
     * @return the value
     */
    public Object getValue () {
        return this.value;
    }

}
