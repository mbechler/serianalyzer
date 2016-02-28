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


import org.jboss.jandex.DotName;
import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class FieldReference extends BaseType implements SimpleType {

    private DotName owner;
    private String name;
    private Type type;
    private boolean isThis;


    /**
     * @param owner
     * @param name
     * @param t
     * @param tainted
     */
    public FieldReference ( DotName owner, String name, Type t, boolean tainted ) {
        this(owner, name, t, tainted, false);
    }


    /**
     * @param owner
     * @param name
     * @param t
     * @param tainted
     * @param isThis
     */
    public FieldReference ( DotName owner, String name, Type t, boolean tainted, boolean isThis ) {
        super(tainted, String.format("%s->%s (%s)", owner, name, t)); //$NON-NLS-1$
        this.owner = owner;
        this.name = name;
        this.type = t;
        this.isThis = isThis;
    }


    /**
     * @return the owner
     */
    public DotName getOwner () {
        return this.owner;
    }


    /**
     * @return the name
     */
    public String getName () {
        return this.name;
    }


    /**
     * @return the type
     */
    @Override
    public Type getType () {
        return this.type;
    }


    /**
     * @return the isThis
     */
    public boolean isThis () {
        return this.isThis;
    }
}
