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
 * Created: 16.11.2015 by mbechler
 */
package serianalyzer;


import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.Set;

import org.apache.log4j.Logger;
import org.jboss.jandex.Index;
import org.objectweb.asm.Type;


/**
 * @author mbechler
 */
public class SerianalyzerState implements Serializable {

    enum Stage {

        CHECK_CLASS, CHECK_METHOD, ANALYSIS_COMPLETE

    }

    private Stage stage = Stage.CHECK_CLASS;

    /**
     * 
     */
    private static final long serialVersionUID = -6684125985594751877L;
    private Set<MethodReference> initial = new HashSet<>();

    private Set<MethodReference> safe = new HashSet<>();
    private Queue<MethodReference> toCheck = new LinkedList<>();

    private Map<MethodReference, Set<MethodReference>> known = new HashMap<>();
    private Map<MethodReference, Set<MethodReference>> methodCallers = new HashMap<>();
    private Map<MethodReference, Set<MethodReference>> methodCallees = new HashMap<>();
    private Set<MethodReference> reportMethods = new HashSet<>();
    private Set<String> instantiableTypes = new HashSet<>();
    private Set<String> forcedInstantiable = new HashSet<>();
    private Map<String, Set<MethodReference>> instantiatedThrough = new HashMap<>();
    private Set<MethodReference> checkedReturnType = new HashSet<>();
    private transient Map<MethodReference, Type> returnTypes = new HashMap<>();
    private Set<MethodReference> staticPuts = new HashSet<>();
    private Benchmark bench = new Benchmark();
    private transient Map<MethodReference, Boolean> checkedCache = new HashMap<>();


    /**
     * 
     */
    public SerianalyzerState () {}


    /**
     * @return the bench
     */
    public Benchmark getBench () {
        return this.bench;
    }


    /**
     * @return currently running analysis stage
     */
    public Stage getStage () {
        return this.stage;
    }


    void setStage ( Stage stage ) {
        this.stage = stage;
    }


    private void writeObject ( ObjectOutputStream oos ) throws IOException {
        oos.defaultWriteObject();

        oos.writeInt(this.returnTypes.size());
        for ( Entry<MethodReference, Type> entry : this.returnTypes.entrySet() ) {
            oos.writeObject(entry.getKey());
            oos.writeUTF(entry.getValue().toString());
        }
    }


    private void readObject ( ObjectInputStream ois ) throws ClassNotFoundException, IOException {
        ois.defaultReadObject();

        int cnt = ois.readInt();
        Map<MethodReference, Type> retTypes = new HashMap<>();
        for ( int i = 0; i < cnt; i++ ) {
            MethodReference ref = (MethodReference) ois.readObject();
            Type t = Type.getType(ois.readUTF());
            retTypes.put(ref, t);
        }
        this.returnTypes = retTypes;
    }


    /**
     * 
     * @param r
     * @return whether the referenced type is instantiable
     */
    public boolean isInstantiable ( MethodReference r ) {
        return this.instantiableTypes.contains(r.getTypeNameString());
    }


    /**
     * @param s
     * @param toRemove
     */
    boolean remove ( MethodReference s, Set<MethodReference> toRemove, RemovalReason r, SerianalyzerConfig cfg ) {
        if ( toRemove.contains(s) ) {
            return false;
        }
        toRemove.add(s);

        Logger cl = Verbose.getPerMethodLogger(s);
        if ( cl.isDebugEnabled() ) {
            cl.debug(String.format("%s, removing call %s", r, s)); //$NON-NLS-1$
        }

        Set<MethodReference> calls = this.methodCallers.remove(s);

        if ( calls != null ) {
            for ( MethodReference caller : calls ) {
                Set<MethodReference> callerCalls = this.methodCallees.get(caller);
                if ( callerCalls != null ) {
                    callerCalls.remove(s);
                }
            }
        }
        return true;
    }


    /**
     * @param typeName
     * @param methodReference
     * @param force
     */
    void trackInstantiable ( String tn, MethodReference methodReference, SerianalyzerConfig cfg, boolean force ) {
        if ( force ) {
            this.forcedInstantiable.add(tn);
        }
        this.instantiableTypes.add(tn);
        Set<MethodReference> set = this.instantiatedThrough.get(tn);
        Logger cl = Verbose.getPerClassLogger(tn);
        if ( set == null ) {
            set = new HashSet<>();
            if ( this.instantiatedThrough.put(tn, set) == null ) {
                if ( cl.isDebugEnabled() ) {
                    cl.debug(String.format("Adding instantiable type %s for %s", tn, methodReference)); //$NON-NLS-1$
                }
            }
        }
        set.add(methodReference.comparable());
    }


    /**
     * @param typeName
     * @return whether the type is definitely instantiable
     */
    public boolean isForcedInstantiable ( String typeName ) {
        return this.forcedInstantiable.contains(typeName);
    }


    /**
     * @param methodReference
     * @param cal
     */
    void traceCalls ( MethodReference methodReference, Set<MethodReference> cal ) {
        MethodReference called = methodReference.comparable();
        Logger cl = Verbose.getPerClassLogger(called.getTypeNameString());
        if ( cl.isDebugEnabled() ) {
            cl.debug(String.format("Adding call to %s by %s", methodReference, cal)); //$NON-NLS-1$
        }
        Set<MethodReference> calling = this.methodCallers.get(called);
        if ( calling == null ) {
            calling = new HashSet<>();
            this.methodCallers.put(called, calling);
        }
        if ( cal != null ) {
            for ( MethodReference ref : cal ) {
                MethodReference r = ref.comparable();
                if ( !r.equals(called) ) {
                    calling.add(r);
                }
            }
        }

        if ( cal != null ) {
            for ( MethodReference caller : cal ) {
                MethodReference comparable = caller.comparable();
                Set<MethodReference> callees = this.methodCallees.get(comparable);
                if ( !called.equals(comparable) ) {
                    if ( callees == null ) {
                        this.methodCallees.put(comparable, new HashSet<>(Arrays.asList(called)));
                    }
                    else {
                        callees.add(called);
                    }
                }
            }
        }

    }


    /**
     * @param ref
     * @param retType
     */
    public void foundReturnType ( MethodReference ref, Type retType ) {
        MethodReference c = ref.comparable();
        this.checkedReturnType.add(c);
    }


    /**
     * @param i
     * @param ignoreNonFound
     * @param ref
     * @param retType
     * @param sigType
     * @throws SerianalyzerException
     */
    public void foundImprovedReturnType ( Index i, boolean ignoreNonFound, MethodReference ref, Type retType, Type sigType )
            throws SerianalyzerException {
        MethodReference c = ref.comparable();
        this.checkedReturnType.add(c);

        if ( "java.lang.Object".equals(sigType.getClassName()) //$NON-NLS-1$
                || ( "java.io.Serializable".equals(sigType.getClassName()) && //$NON-NLS-1$
                        !"java.lang.Object".equals(retType.getClassName()) ) ) { //$NON-NLS-1$
            if ( this.returnTypes.put(c, retType) != null ) {
                this.bench.improvedReturnType();
            }
            return;
        }
        else if ( sigType.getSort() != Type.OBJECT || sigType.getClassName().endsWith("[]") ) { //$NON-NLS-1$
            return;
        }

        if ( this.returnTypes.containsKey(c) ) {
            return;
        }

        Type moreConcreteType = TypeUtil.getMoreConcreteType(i, ignoreNonFound, retType, sigType);

        if ( this.returnTypes.put(c, moreConcreteType) == null ) {
            if ( moreConcreteType.equals(retType) && !moreConcreteType.equals(sigType) ) {
                this.bench.improvedReturnType();
            }
            else {
                this.bench.nonImprovedReturnType();
            }
        }

    }


    /**
     * @param ref
     */
    void markSafe ( MethodReference ref ) {
        this.safe.add(ref.comparable());
    }


    /**
     * @param ref
     */
    void reportCall ( MethodReference ref ) {
        this.reportMethods.add(ref.comparable());
        this.trackKnown(ref);
    }


    /**
     * @param ref
     */
    void addInitial ( MethodReference ref ) {
        this.initial.add(ref.comparable());
    }


    /**
     * @return the initial
     */
    public Set<MethodReference> getInitial () {
        return this.initial;
    }


    /**
     * @return the total number of found method calls
     */
    public long getTotalKnownCount () {
        long total = 0;
        for ( Set<MethodReference> set : this.known.values() ) {
            if ( set != null ) {
                total += set.size();
            }
        }
        return total;
    }


    /**
     * @param method
     * @return the known instances for the method call
     */
    public Set<MethodReference> getAlreadyKnown ( MethodReference method ) {
        MethodReference cmp = method.comparable();
        Set<MethodReference> set = this.known.get(cmp);
        if ( set == null ) {
            return Collections.EMPTY_SET;
        }
        return set;
    }


    /**
     * @param method
     */
    public void trackKnown ( MethodReference method ) {
        MethodReference cmp = method.comparable();

        Logger cl = Verbose.getPerMethodLogger(cmp);
        if ( cl.isDebugEnabled() ) {
            cl.debug(String.format("Handled call to %s", cmp)); //$NON-NLS-1$
        }

        Set<MethodReference> set = this.known.get(cmp);

        if ( set == null ) {
            set = new HashSet<>();
            this.known.put(cmp, set);
        }
        set.add(method);
    }


    /**
     * @param methodReference
     * @return whether a method call is already known
     */
    public boolean isKnown ( MethodReference methodReference ) {
        MethodReference cmp = methodReference.comparable();
        Set<MethodReference> set = this.known.get(cmp);
        if ( set == null ) {
            return false;
        }
        return set.contains(methodReference);
    }


    /**
     * @param methodReference
     * @return number of known different argument types
     */
    public int countKnown ( MethodReference methodReference ) {
        MethodReference cmp = methodReference.comparable();
        Set<MethodReference> set = this.known.get(cmp);
        if ( set == null ) {
            return 0;
        }
        return set.size();
    }


    /**
     * @param toRemove
     * @return whether any change was made
     */
    public boolean removeAllKnown ( Set<MethodReference> toRemove ) {
        boolean anyChanged = false;
        for ( MethodReference ref : toRemove ) {
            MethodReference cmp = ref.comparable();
            anyChanged |= this.known.remove(cmp) != null;
        }
        return anyChanged;
    }


    /**
     * @return the safe
     */
    public Set<MethodReference> getSafe () {
        return this.safe;
    }


    /**
     * @return the toCheck
     */
    public Queue<MethodReference> getToCheck () {
        return this.toCheck;
    }


    /**
     * @return the methodCallers
     */
    public Map<MethodReference, Set<MethodReference>> getMethodCallers () {
        return this.methodCallers;
    }


    /**
     * @return the methodCallees
     */
    public Map<MethodReference, Set<MethodReference>> getMethodCallees () {
        return this.methodCallees;
    }


    /**
     * @return the nativeMethods
     */
    public Set<MethodReference> getReportMethods () {
        return this.reportMethods;
    }


    /**
     * @return the instantiableTypes
     */
    public Set<String> getInstantiableTypes () {
        return this.instantiableTypes;
    }


    /**
     * @return the instantiatedThrough
     */
    public Map<String, Set<MethodReference>> getInstantiatedThrough () {
        return this.instantiatedThrough;
    }


    /**
     * @return the checkedReturnType
     */
    public Set<MethodReference> getCheckedReturnType () {
        return this.checkedReturnType;
    }


    /**
     * @return the returnTypes
     */
    public Map<MethodReference, Type> getReturnTypes () {
        return this.returnTypes;
    }


    /**
     * @return the staticPuts
     */
    public Set<MethodReference> getStaticPuts () {
        return this.staticPuts;
    }


    /**
     * @param elem
     * @return the maximum known taint status for a method
     */
    public MethodReference getMaximumTaintStatus ( MethodReference elem ) {
        MethodReference cur = elem;
        for ( MethodReference methodReference : getAlreadyKnown(elem) ) {
            cur = cur.maxTaint(methodReference);
        }
        return cur;
    }


    /**
     * @return the checking cache
     */
    public Map<MethodReference, Boolean> getCheckedCache () {
        return this.checkedCache;
    }


    /**
     * @return all known method references
     */
    public int countAllKnown () {
        return this.known.size();
    }

}