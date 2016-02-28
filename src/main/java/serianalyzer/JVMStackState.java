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
 * Created: 15.11.2015 by mbechler
 */
package serianalyzer;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import org.apache.log4j.Logger;
import org.objectweb.asm.Type;

import serianalyzer.types.BaseType;
import serianalyzer.types.BasicConstant;
import serianalyzer.types.BasicVariable;
import serianalyzer.types.MultiAlternatives;
import serianalyzer.types.SimpleType;


/**
 * @author mbechler
 *
 */
public class JVMStackState {

    private static final Logger log = Logger.getLogger(JVMStackState.class);

    private Stack<BaseType> stack = new Stack<>();
    @SuppressWarnings ( "unchecked" )
    private Set<BaseType>[] variables = new Set[255];


    /**
     * @return the removed top stack element
     * 
     */
    public BaseType pop () {
        if ( !this.stack.isEmpty() ) {
            return this.stack.pop();
        }
        return null;
    }


    /**
     * @param i
     * @return the removed i top stack elements
     * 
     */
    public List<BaseType> pop ( int i ) {
        int rem = i;
        List<BaseType> objs = new ArrayList<>();
        while ( !this.stack.isEmpty() && rem > 0 ) {
            objs.add(this.stack.pop());
            rem--;
        }

        Collections.reverse(objs);
        return objs;
    }


    /**
     * @return the removed top stack word
     */
    public List<BaseType> popWord () {
        BaseType o1 = pop();
        Type t = getType(o1, new HashSet<>());
        if ( t == Type.DOUBLE_TYPE || t == Type.LONG_TYPE ) {
            return Arrays.asList(o1);
        }
        else if ( t != null && t != Type.VOID_TYPE ) {
            BaseType o2 = pop();
            return Arrays.asList(o2, o1);
        }

        return Collections.EMPTY_LIST;
    }


    /**
     * @param objs
     */
    public void pushWord ( List<BaseType> objs ) {
        for ( BaseType o : objs ) {
            push(o);
        }
    }


    /**
     * @param var
     */
    public void push ( BaseType var ) {
        this.stack.push(var);
    }


    /**
     * 
     */
    public void clear () {
        this.stack.clear();
    }


    /**
     * @return whether the stack is empty
     */
    public boolean isEmpty () {
        return this.stack.isEmpty();
    }


    /**
     * @param var
     * @return the variable alternatives
     */
    public Set<BaseType> getVariable ( int var ) {
        Set<BaseType> v = this.variables[ var ];
        if ( v == null ) {
            this.variables[ var ] = new HashSet<>();
            v = this.variables[ var ];
        }
        return v;
    }


    /**
     * @return all variables
     */
    public Set<BaseType>[] getVariables () {
        return this.variables;
    }


    /**
     * @param o1
     * @param found
     * @return
     */
    private static Type getType ( BaseType o1, Set<BaseType> found ) {
        if ( o1 == null ) {
            return Type.VOID_TYPE;
        }

        if ( found.contains(o1) ) {
            throw new IllegalArgumentException("Recursion"); //$NON-NLS-1$
        }

        found.add(o1);

        if ( o1 instanceof SimpleType ) {
            return ( (SimpleType) o1 ).getType();
        }
        else if ( o1 instanceof MultiAlternatives ) {
            return ( (MultiAlternatives) o1 ).getCommonType();
        }
        else {
            return Type.VOID_TYPE;
        }
    }


    /**
     * @param vals
     * @return merged base type
     */
    public static BaseType merge ( List<BaseType> vals ) {
        boolean allConstant = true;
        boolean anyTainted = false;
        Type t = Type.VOID_TYPE;

        for ( BaseType o : vals ) {
            if ( o == null ) {
                t = Type.VOID_TYPE;
                anyTainted = true;
                break;
            }

            anyTainted |= o.isTainted();
            if ( ! ( o instanceof BasicConstant ) ) {
                allConstant = false;
            }

            Type type = getType(o, new HashSet<>());
            if ( type == null || ( t != Type.VOID_TYPE && !t.equals(type) && ( t.getSort() == Type.OBJECT || type.getSort() == Type.OBJECT ) ) ) {
                log.error("Incompatible operands in operation " + type + " and " + t); //$NON-NLS-1$ //$NON-NLS-2$
                t = Type.VOID_TYPE;
                allConstant = false;
                break;
            }

            t = type;
        }

        if ( allConstant ) {
            return new BasicConstant(t, null, anyTainted);
        }

        if ( t == Type.VOID_TYPE ) {
            log.debug("Could not determine computation result type " + t); //$NON-NLS-1$
        }

        return new BasicVariable(t, "comp result " + t, anyTainted); //$NON-NLS-1$
    }


    /**
     * @param i
     */
    public void merge ( int i ) {
        this.push(JVMStackState.merge(this.pop(i)));
    }
}
