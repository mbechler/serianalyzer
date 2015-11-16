/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 16.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Queue;
import java.util.Set;

import org.jboss.jandex.DotName;
import org.jboss.jandex.Index;
import org.objectweb.asm.Type;


/**
 * @author mbechler
 */
public class SerianalyzerState implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -6684125985594751877L;

    private Set<MethodReference> initial = new HashSet<>();
    private Set<MethodReference> known = new HashSet<>();
    private Set<MethodReference> safe = new HashSet<>();
    private Queue<MethodReference> toCheck = new LinkedList<>();
    private Map<MethodReference, Set<MethodReference>> methodCallers = new HashMap<>();
    private Map<MethodReference, Set<MethodReference>> methodCallees = new HashMap<>();
    private Set<MethodReference> nativeMethods = new HashSet<>();
    private Set<String> instantiableTypes = new HashSet<>();
    private Map<String, Set<MethodReference>> instantiatedThrough = new HashMap<>();
    private Set<MethodReference> checkedReturnType = new HashSet<>();
    private transient Map<MethodReference, Type> returnTypes = new HashMap<>();
    private Set<MethodReference> staticPuts = new HashSet<>();
    private Map<MethodReference, MethodReference> maximumTaintStatus = new HashMap<>();

    private Benchmark bench = new Benchmark();


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
        return this.instantiableTypes.contains(r.getTypeName().toString());
    }


    /**
     * @param s
     * @param toRemove
     */
    boolean remove ( MethodReference s, Set<MethodReference> toRemove ) {
        if ( toRemove.contains(s) ) {
            return false;
        }
        toRemove.add(s);

        Set<MethodReference> calls = this.methodCallers.remove(s);
        if ( calls != null ) {
            for ( MethodReference caller : calls ) {
                Set<MethodReference> callerCalls = this.methodCallees.get(caller);
                if ( callerCalls != null ) {
                    if ( !callerCalls.remove(s) ) {

                    }
                    if ( callerCalls.isEmpty() ) {
                        remove(caller, toRemove);
                    }
                }
            }
        }

        Set<MethodReference> callees = this.methodCallees.remove(s);
        if ( callees != null ) {
            for ( MethodReference callee : callees ) {
                Set<MethodReference> calleeCallers = this.methodCallers.get(callee);
                if ( calleeCallers != null ) {
                    if ( !calleeCallers.remove(s) ) {

                    }
                    if ( calleeCallers.isEmpty() ) {
                        remove(callee, toRemove);
                    }
                }
            }
        }
        return true;
    }


    /**
     * @param typeName
     * @param methodReference
     */
    void trackInstantiable ( DotName typeName, MethodReference methodReference ) {
        String tn = typeName.toString();
        this.instantiableTypes.add(tn);
        Set<MethodReference> set = this.instantiatedThrough.get(tn);
        if ( set == null ) {
            set = new HashSet<>();
            this.instantiatedThrough.put(tn, set);
        }

        trackMaximumTaint(methodReference);
        set.add(methodReference);
    }


    /**
     * @param methodReference
     */
    void trackMaximumTaint ( MethodReference methodReference ) {
        MethodReference cmp = methodReference.comparable();
        MethodReference maxTaint = this.maximumTaintStatus.get(cmp);
        if ( maxTaint == null ) {
            maxTaint = methodReference;
        }
        else {
            maxTaint = maxTaint.maxTaint(methodReference);
        }
        this.maximumTaintStatus.put(cmp, maxTaint);
    }


    /**
     * @param methodReference
     * @param cal
     */
    void traceCalls ( MethodReference methodReference, Set<MethodReference> cal ) {

        MethodReference called = methodReference.comparable();
        trackMaximumTaint(methodReference);

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
                trackMaximumTaint(caller);
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
        this.safe.add(ref);
    }


    /**
     * @param ref
     */
    void nativeCall ( MethodReference ref ) {
        this.nativeMethods.add(ref.comparable());
        this.known.add(ref.comparable());
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
     * @return the known
     */
    public Set<MethodReference> getKnown () {
        return this.known;
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
    public Set<MethodReference> getNativeMethods () {
        return this.nativeMethods;
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
     * @return the maximumTaintStatus
     */
    public Map<MethodReference, MethodReference> getMaximumTaintStatus () {
        return this.maximumTaintStatus;
    }


    /**
     * @param knownIgnoreTaint
     */
    void setKnown ( Set<MethodReference> knownIgnoreTaint ) {
        this.known = knownIgnoreTaint;
    }
}