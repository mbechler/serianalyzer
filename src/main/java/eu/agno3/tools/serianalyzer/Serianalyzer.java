/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 11.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;

import org.apache.log4j.Logger;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
import org.jboss.jandex.Index;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public class Serianalyzer {

    private static final Logger log = Logger.getLogger(Serianalyzer.class);

    private SerianalyzerInput input;
    private SerianalyzerState state;


    /**
     * @param input
     */
    public Serianalyzer ( SerianalyzerInput input ) {
        this.input = input;
        this.state = new SerianalyzerState();
    }


    /**
     * @throws SerianalyzerException
     * 
     */
    public void analyze () throws SerianalyzerException {
        restoreOrRunAnalysis();
        log.info(String.format("Found a total %d method reachable", this.state.getKnown().size())); //$NON-NLS-1$
        log.info(String.format("Found a total %d native method initially reachable", this.state.getNativeMethods().size())); //$NON-NLS-1$
        log.info(String.format("Found a total %d safe methods", this.state.getSafe().size())); //$NON-NLS-1$
        filterAndDump();
    }


    /**
     * @throws SerianalyzerException
     * 
     */
    private void restoreOrRunAnalysis () throws SerianalyzerException {
        if ( this.input.getConfig().getRestoreFrom() != null ) {
            restore();
        }
        else {
            runAnalysis();
            save();
        }
    }


    /**
     * 
     */
    private void filterAndDump () {
        prefilterMethods();
        log.info(String.format("Found a total %d native methods remaining", this.state.getNativeMethods().size())); //$NON-NLS-1$
        List<MethodReference> dump = new ArrayList<>(this.state.getNativeMethods());
        Collections.sort(dump, new MethodReferenceComparator());

        Set<DotName> usedInstantiable = new HashSet<>();
        long nonWhitelist = dumpMethodCalls(dump, usedInstantiable, "Potentially unsafe native call "); //$NON-NLS-1$
        log.info(String.format("Found %d non-whitelisted native methods", nonWhitelist)); //$NON-NLS-1$
        long stPuts = dumpMethodCalls(this.state.getStaticPuts(), usedInstantiable, "Potentially unsafe static put in "); //$NON-NLS-1$
        log.info(String.format("Found %d potentially unsafe static puts", stPuts)); //$NON-NLS-1$

        if ( this.input.getConfig().isDumpInstantiationInfo() ) {
            dumpInstantiable(usedInstantiable);
        }
        this.state.getBench().dump();
    }


    /**
     * @param saveTo
     * @throws SerianalyzerException
     */
    private void save () throws SerianalyzerException {
        if ( this.input.getConfig().getSaveTo() != null ) {
            log.info("Saving state"); //$NON-NLS-1$
            try ( FileOutputStream fos = new FileOutputStream(this.input.getConfig().getSaveTo());
                  ObjectOutputStream oos = new ObjectOutputStream(fos) ) {
                oos.writeObject(this.state);
            }
            catch ( IOException e ) {
                throw new SerianalyzerException("Failed to write state", e); //$NON-NLS-1$
            }
        }
    }


    /**
     * 
     * @param is
     * @throws SerianalyzerException
     */
    private void restore () throws SerianalyzerException {
        if ( this.input.getConfig().getRestoreFrom() != null ) {
            log.info("Loading state"); //$NON-NLS-1$
            try ( FileInputStream fis = new FileInputStream(this.input.getConfig().getRestoreFrom());
                  ObjectInputStream ois = new ObjectInputStream(fis) ) {
                this.state = (SerianalyzerState) ois.readObject();
            }
            catch (
                IOException |
                ClassNotFoundException e ) {
                throw new SerianalyzerException("Failed to restore state", e); //$NON-NLS-1$
            }
            filterAndDump();
        }
    }


    /**
     * @throws SerianalyzerException
     */
    private void runAnalysis () throws SerianalyzerException {
        Set<ClassInfo> serializable = this.input.getIndex().getAllKnownImplementors(DotName.createSimple(Serializable.class.getName()));
        log.info(String.format("Found %d serializable classes", serializable.size())); //$NON-NLS-1$

        for ( ClassInfo ci : serializable ) {
            if ( this.input.getConfig().isWhitelistedClass(ci.name().toString()) ) {
                continue;
            }
            checkClass(ci);
        }

        log.info(String.format("Found %d initial methods to check", this.state.getToCheck().size())); //$NON-NLS-1$

        while ( !this.state.getToCheck().isEmpty() ) {
            MethodReference method = this.state.getToCheck().poll();
            this.state.getKnown().add(method);
            doCheckMethod(method);
        }
    }


    /**
     * 
     */
    private void prefilterMethods () {
        log.info("Running filtering"); //$NON-NLS-1$
        removeIgnoreTaint(this.state.getSafe(), this.state.getNativeMethods());
        this.state.getSafe().addAll(this.input.getConfig().getNativeWhiteList());
        this.state.getNativeMethods().removeAll(this.input.getConfig().getNativeWhiteList());

        Set<MethodReference> knownIgnoreTaint = new HashSet<>();
        for ( MethodReference ref : this.state.getKnown() ) {
            knownIgnoreTaint.add(ref.comparable());
        }
        this.state.setKnown(knownIgnoreTaint);
        for ( MethodReference s : this.state.getSafe() ) {
            removeSafeCalls(s);
        }

        log.info(String.format("Remaining methods %d", this.state.getKnown().size())); //$NON-NLS-1$
        Set<MethodReference> toRemove = new HashSet<>();
        boolean anyChanged = true;
        int i = 0;
        while ( anyChanged ) {
            i++;
            log.info("Filtering: iteration " + i + "..."); //$NON-NLS-1$ //$NON-NLS-2$
            anyChanged = false;
            anyChanged |= removeRecursiveInstatiations();
            Set<MethodReference> known = new HashSet<>(this.state.getMethodCallers().keySet());
            for ( MethodReference kn : known ) {
                anyChanged |= removeNonReachable(kn, this.state.getInitial(), toRemove);
            }
            log.info(String.format("Removing %d non-instantiable", toRemove.size())); //$NON-NLS-1$
            this.state.getKnown().removeAll(toRemove);
            this.state.getStaticPuts().removeAll(toRemove);
            log.info(String.format("Remaining methods %d", this.state.getKnown().size())); //$NON-NLS-1$
            removeIgnoreTaint(this.state.getNativeMethods(), toRemove);
            toRemove.clear();
        }
        log.info("Finished filtering"); //$NON-NLS-1$
    }


    /**
     * @return
     * 
     */
    private boolean removeRecursiveInstatiations () {
        Set<String> toRemove = new HashSet<>();
        for ( String typeName : this.state.getInstantiableTypes() ) {

            if ( TypeUtil.isSerializable(this.input.getIndex(), this.input.getIndex().getClassByName(DotName.createSimple(typeName))) ) {
                continue;
            }

            if ( checkAllRecursive(typeName, this.state.getInitial()) ) {
                log.debug("All instantiations are recursive for " + typeName); //$NON-NLS-1$
                toRemove.add(typeName);
            }
        }
        return this.state.getInstantiableTypes().removeAll(toRemove);
    }


    /**
     * @param dump
     * @param usedInstantiable
     * @return
     */
    private long dumpMethodCalls ( Collection<MethodReference> dump, Set<DotName> usedInstantiable, String msg ) {
        long nonWhitelist = 0;
        for ( MethodReference cal : dump ) {
            cal = cal.comparable();
            Set<MethodReference> callers = this.state.getMethodCallers().get(cal);
            if ( callers == null || callers.isEmpty() ) {
                continue;
            }

            if ( !dumpBacktraces(cal, this.state.getInitial(), usedInstantiable, "", this.input.getConfig().getMaxDisplayDumps()) ) { //$NON-NLS-1$
                continue;
            }
            System.err.println(msg + cal);
            nonWhitelist++;
        }
        return nonWhitelist;
    }


    private void dumpInstantiable ( Set<DotName> usedInstantiable ) {
        System.out.println(String.format("Used %d non-serializable instantiable types: ", usedInstantiable.size())); //$NON-NLS-1$
        for ( DotName name : usedInstantiable ) {
            traceInstantiation("  ", name, new HashSet<>()); //$NON-NLS-1$
        }

    }


    /**
     * @param toRemove
     * @return
     */
    private static boolean removeIgnoreTaint ( Set<MethodReference> target, Set<MethodReference> toRemove ) {
        Set<MethodReference> reallyRemove = new HashSet<>();
        for ( MethodReference ref : target ) {
            if ( toRemove.contains(ref.comparable()) ) {
                reallyRemove.add(ref);
            }
        }
        return target.removeAll(reallyRemove);
    }


    private boolean dumpBacktraces ( MethodReference start, Set<MethodReference> targets, Set<DotName> usedInstantiable, String prefix, int limit ) {
        MethodReference comparable = start.comparable();
        List<MethodReference> rootPath = new ArrayList<>(Arrays.asList(comparable));
        return dumpBacktraces(
            new LinkedList<>(Arrays.asList(rootPath)),
            targets,
            usedInstantiable,
            prefix,
            new HashSet<>(Arrays.asList(comparable)),
            limit);
    }


    /**
     * @param cal
     * @param i
     */
    private boolean dumpBacktraces ( Queue<List<MethodReference>> toVisit, Set<MethodReference> targets, Set<DotName> usedInstantiable,
            String prefix, Set<MethodReference> visited, int initialLimit ) {

        int limit = initialLimit;

        boolean anyFound = false;
        while ( !toVisit.isEmpty() ) {
            List<MethodReference> p = toVisit.poll();
            MethodReference r = p.get(p.size() - 1);

            if ( targets.contains(r) ) {
                limit--;

                for ( MethodReference elem : p ) {
                    System.out.print(prefix + this.state.getMaximumTaintStatus().get(elem.comparable()));
                    if ( TypeUtil.isSerializable(this.input.getIndex(), this.input.getIndex().getClassByName(elem.getTypeName())) ) {
                        System.out.println(" serializable"); //$NON-NLS-1$
                    }
                    else if ( this.state.isInstantiable(elem) ) {
                        usedInstantiable.add(elem.getTypeName());
                        System.out.println(" instantiable"); //$NON-NLS-1$
                    }
                    else {
                        System.out.println();
                    }
                }
                System.out.println();
                anyFound = true;
                if ( limit <= 0 ) {
                    return true;
                }
                continue;
            }

            Set<MethodReference> set = this.state.getMethodCallers().get(r);

            if ( set != null && !set.isEmpty() ) {
                for ( MethodReference ref : set ) {
                    if ( !visited.contains(ref) && !r.equals(ref) ) {
                        List<MethodReference> np = new ArrayList<>(p);
                        if ( filterPath(np) ) {
                            this.getState().getBench().heuristicFilter();
                            continue;
                        }
                        np.add(ref);
                        toVisit.add(np);
                        visited.add(ref);
                    }
                }

            }
        }

        return anyFound;
    }


    /**
     * @param string
     * @param typeName
     */
    private void traceInstantiation ( String prefix, DotName typeName, Set<MethodReference> found ) {

        if ( checkAllRecursive(typeName.toString(), this.state.getInitial()) ) {
            log.warn("All instantiations are recursive for " + typeName); //$NON-NLS-1$
            return;
        }

        int limit = 3;

        Set<MethodReference> set = this.state.getInstantiatedThrough().get(typeName.toString());
        if ( set != null ) {
            System.out.println(prefix + typeName + " instantiable through:"); //$NON-NLS-1$
            for ( MethodReference r : set ) {
                if ( limit <= 0 ) {
                    return;
                }

                MethodReference comparable = r.comparable();
                if ( found.contains(comparable) || this.input.getConfig().isWhitelisted(comparable) ) {
                    continue;
                }

                found.add(comparable);
                System.out.print(prefix + "-> " + this.state.getMaximumTaintStatus().get(comparable)); //$NON-NLS-1$
                boolean nonSerializable = !TypeUtil.isSerializable(this.getIndex(), this.getIndex().getClassByName(r.getTypeName()));
                Set<MethodReference> callers = this.state.getMethodCallers().get(comparable);

                if ( !nonSerializable && ( callers == null || callers.isEmpty() ) ) {
                    log.warn("No callers found for " + typeName); //$NON-NLS-1$
                    continue;
                }

                if ( nonSerializable ) {
                    System.out.println();
                    //traceInstantiation(prefix + " ", r.getTypeName(), found); //$NON-NLS-1$
                }
                else {
                    System.out.println(" serializable"); //$NON-NLS-1$
                }

                dumpBacktraces(comparable, this.state.getInitial(), new HashSet<>(), prefix + "   * ", 1); //$NON-NLS-1$

                limit--;
            }
        }
        else {
            log.warn("No instantiations found for " + typeName); //$NON-NLS-1$
        }
    }


    /**
     * @param string
     */
    private boolean checkAllRecursive ( String typeName, Set<MethodReference> targets ) {
        Set<MethodReference> i = this.state.getInstantiatedThrough().get(typeName);
        if ( i == null || i.isEmpty() ) {
            log.warn("Instantiated through is empty " + typeName); //$NON-NLS-1$
            return true;
        }

        Queue<MethodReference> toVisit = new LinkedList<>(i);
        Set<MethodReference> visited = new HashSet<>();
        visited.addAll(i);
        while ( !toVisit.isEmpty() ) {
            MethodReference r = toVisit.poll();

            if ( targets.contains(r) ) {
                return false;
            }

            DotName refTypeName = r.getTypeName();
            ClassInfo classByName = this.input.getIndex().getClassByName(refTypeName);

            if ( TypeUtil.isSerializable(this.input.getIndex(), classByName) ) {
                return false;
            }

            Set<MethodReference> set = this.state.getInstantiatedThrough().get(refTypeName.toString());
            if ( set != null && !set.isEmpty() ) {
                for ( MethodReference ref : set ) {
                    Set<MethodReference> callers = this.state.getMethodCallers().get(ref.comparable());
                    if ( callers == null || callers.isEmpty() ) {
                        log.debug("No callers found for " + ref); //$NON-NLS-1$
                        continue;
                    }

                    for ( MethodReference c : callers ) {
                        if ( c.isStatic() ) {
                            Set<MethodReference> origCallers = new HashSet<>();
                            resolveNonStaticCallers(c, origCallers, new HashSet<>());
                            for ( MethodReference oc : origCallers ) {
                                if ( !visited.contains(oc) ) {
                                    toVisit.add(oc);
                                    visited.add(oc);
                                }
                            }
                        }
                        else {
                            if ( !visited.contains(c) ) {
                                toVisit.add(c);
                                visited.add(c);
                            }
                        }
                    }
                }
            }
            else {
                log.debug("No instantiations found for " + refTypeName.toString()); //$NON-NLS-1$
            }
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Only recursive instantiations " + typeName); //$NON-NLS-1$
        }
        return true;

    }


    /**
     * @param c
     */
    private void resolveNonStaticCallers ( MethodReference c, Set<MethodReference> callers, Set<MethodReference> found ) {
        MethodReference comparable = c.comparable();
        if ( callers.contains(comparable) ) {
            return;
        }
        found.add(comparable);
        Set<MethodReference> refs = this.state.getMethodCallers().get(comparable);
        if ( refs == null ) {
            return;
        }
        for ( MethodReference r : refs ) {
            MethodReference rc = r.comparable();
            if ( !found.contains(rc) && r.isStatic() ) {
                resolveNonStaticCallers(r, callers, found);
            }
            else if ( !r.isStatic() ) {
                callers.add(rc);
            }
        }

    }


    /**
     * @param p
     * @return
     */
    private boolean filterPath ( List<MethodReference> p ) {
        if ( !this.input.getConfig().isUseHeuristics() ) {
            return false;
        }
        boolean foundSerializable = false;
        for ( MethodReference r : p ) {
            if ( TypeUtil.isSerializable(this.input.getIndex(), this.input.getIndex().getClassByName(r.getTypeName())) ) {
                foundSerializable = true;
            }
            else if ( foundSerializable && !TypeUtil.isSerializable(this.input.getIndex(), this.input.getIndex().getClassByName(r.getTypeName())) ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Intermediate non serializable type " + p); //$NON-NLS-1$
                }
                return true;
            }
            else if ( !this.state.isInstantiable(r) ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Starts with non instantiable type " + p); //$NON-NLS-1$
                }
                return true;
            }
        }
        return false;
    }


    private boolean removeNonReachable ( MethodReference ref, Set<MethodReference> retainSet, Set<MethodReference> toRemove ) {
        MethodReference s = ref.comparable();
        ClassInfo classByName = this.input.getIndex().getClassByName(s.getTypeName());

        if ( this.input.getConfig().isWhitelisted(s) ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Removing because of whitelist " + s); //$NON-NLS-1$
            }
            return this.state.remove(s, toRemove);
        }

        if ( !retainSet.contains(s) && ( this.state.getMethodCallers().get(s) == null || this.state.getMethodCallers().get(s).isEmpty() ) ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Removing because of missing callers " + s); //$NON-NLS-1$
            }
            return this.state.remove(s, toRemove);
        }

        if ( !s.isInterface() && ( s.isStatic() || TypeUtil.isSerializable(this.input.getIndex(), classByName) || this.state.isInstantiable(s) ) ) {
            return false;
        }

        if ( log.isDebugEnabled() ) {
            log.debug("Removing because uninstantiable " + s); //$NON-NLS-1$
        }
        return this.state.remove(s, toRemove);
    }


    /**
     * @param s
     */
    private void removeSafeCalls ( MethodReference ref ) {
        MethodReference s = ref.comparable();
        if ( !this.state.getKnown().remove(s) ) {
            return;
        }

        Set<MethodReference> calls = this.state.getMethodCallers().get(s);
        if ( calls == null ) {
            return;
        }

        for ( MethodReference caller : calls ) {
            Set<MethodReference> callerCalls = this.state.getMethodCallees().get(caller);
            if ( callerCalls != null ) {
                callerCalls.remove(s);

                if ( callerCalls.isEmpty() ) {
                    removeSafeCalls(caller);
                }
            }
        }
    }


    /**
     * @return the index
     */
    Index getIndex () {
        return this.input.getIndex();
    }


    /**
     * @return the whitelist
     */
    SerianalyzerConfig getConfig () {
        return this.input.getConfig();
    }


    /**
     * @param ci
     * @throws SerianalyzerException
     */
    private void checkClass ( ClassInfo ci ) throws SerianalyzerException {
        try ( InputStream data = this.input.getClassData(ci.name()) ) {
            if ( data == null ) {
                log.error("No class data for " + ci.name()); //$NON-NLS-1$
                return;
            }
            boolean serializable = TypeUtil.isSerializable(this.input.getIndex(), ci);
            ClassReader cr = new ClassReader(data);
            SerianalyzerClassSerializationVisitor visitor = new SerianalyzerClassSerializationVisitor(this, ci.name(), serializable);
            cr.accept(visitor, 0);
            if ( serializable ) {
                checkClass(this.input.getIndex().getClassByName(ci.superName()));
            }
            else if ( !visitor.isFoundDefaultConstructor() ) {
                log.trace("No default constructor found in first non-serializable parent " + ci.name()); //$NON-NLS-1$
            }
        }
        catch ( IOException e ) {
            throw new SerianalyzerException("Failed to read class data" + ci.name(), e); //$NON-NLS-1$
        }
    }


    /**
     * @param initialRef
     * @param cal
     * @param wantFixedType
     * @param wantSerializableOnly
     * @return whether the call should be ignored
     */
    public boolean checkMethodCall ( MethodReference initialRef, Set<MethodReference> cal, boolean wantFixedType, boolean wantSerializableOnly ) {

        boolean fixedType = wantFixedType;
        MethodReference methodReference = initialRef;
        boolean serializableOnly = wantSerializableOnly;

        if ( this.input.getConfig().isWhitelisted(methodReference) ) {
            if ( log.isDebugEnabled() ) {
                log.debug("Whitelisted method " + methodReference); //$NON-NLS-1$
            }
            return false;
        }

        if ( this.input.getConfig().restrictToSerializable(methodReference) ) {
            serializableOnly = true;
        }

        DotName overrideType = this.input.getConfig().getFixedType(methodReference);
        if ( overrideType != null ) {
            fixedType = true;
            methodReference = methodReference.adaptToType(overrideType);
        }

        if ( "<init>".equals(methodReference.getMethod()) ) { //$NON-NLS-1$
            this.state.trackInstantiable(methodReference.getTypeName(), methodReference);

        }

        this.state.traceCalls(methodReference, cal);

        if ( this.state.getKnown().contains(methodReference) ) {
            if ( log.isTraceEnabled() ) {
                log.trace("Method already found " + methodReference); //$NON-NLS-1$
            }
            return true;
        }

        if ( this.state.getSafe().contains(methodReference) ) {
            return false;
        }

        this.state.getKnown().add(methodReference);
        Collection<ClassInfo> impls = findImplementors(methodReference, fixedType, serializableOnly, true);

        if ( impls.isEmpty() ) {
            log.trace("No implementations found for " + methodReference); //$NON-NLS-1$
            return false;
        }

        boolean anyFound = false;
        for ( ClassInfo impl : impls ) {
            boolean found = TypeUtil.implementsMethod(methodReference, impl);
            if ( !found ) {
                if ( fixedType ) {
                    log.warn("Method not found in fixed type " + methodReference); //$NON-NLS-1$
                }
                continue;
            }

            MethodReference e = methodReference.adaptToType(impl.name());
            TypeUtil.checkReferenceTyping(this.input.getIndex(), this.input.getConfig().isIgnoreNonFound(), e);
            this.state.traceCalls(e, cal);
            this.state.getKnown().add(e);
            this.state.getToCheck().add(e);
            anyFound = true;
        }

        if ( !anyFound ) {
            log.trace("No usable implementation found for " + methodReference); //$NON-NLS-1$
        }

        return anyFound;

    }


    /**
     * @param t
     * @param sigType
     * @return
     * @throws SerianalyzerException
     */
    Type getMoreConcreteType ( Type a, Type b ) throws SerianalyzerException {
        return TypeUtil.getMoreConcreteType(this.input.getIndex(), this.input.getConfig().isIgnoreNonFound(), a, b);
    }


    /**
     * @param ref
     * @param t
     * @param sigType
     * @throws SerianalyzerException
     */
    public void foundImprovedReturnType ( MethodReference ref, Type t, Type sigType ) throws SerianalyzerException {
        this.state.foundImprovedReturnType(this.input.getIndex(), this.input.getConfig().isIgnoreNonFound(), ref, t, sigType);
    }


    /**
     * @param methodReference
     * @param fixedType
     * @param serializableOnly
     * @return
     */
    private Collection<ClassInfo> findImplementors ( MethodReference methodReference, boolean fixedType, boolean serializableOnly, boolean doBench ) {
        return TypeUtil.findImplementors(methodReference, this.input.getConfig().isIgnoreNonFound(), fixedType, serializableOnly, doBench ? this
                .getState().getBench() : null, getIndex());

    }


    /**
     * @param method
     * @throws SerianalyzerException
     */
    private void doCheckMethod ( MethodReference methodReference ) throws SerianalyzerException {

        if ( log.isTraceEnabled() ) {
            log.trace(String.format("Checking reference %s", methodReference)); //$NON-NLS-1$
        }

        try ( InputStream data = this.input.getClassData(methodReference.getTypeName()) ) {
            if ( data == null ) {
                log.error("No class data for " + methodReference.getTypeName()); //$NON-NLS-1$
                return;
            }

            if ( this.input.getConfig().isWhitelisted(methodReference) ) {
                return;
            }

            ClassReader cr = new ClassReader(data);
            SerianalyzerClassMethodVisitor visitor = new SerianalyzerClassMethodVisitor(this, methodReference, methodReference.getTypeName());
            cr.accept(visitor, 0);

            if ( !visitor.isFound() ) {
                ClassInfo superclass = this.input.getIndex().getClassByName(methodReference.getTypeName());
                if ( superclass == null ) {
                    throw new SerianalyzerException("Superclass not found " + methodReference.getTypeName()); //$NON-NLS-1$
                }
                checkMethodCall(methodReference.adaptToType(superclass.name()), Collections.singleton(methodReference), true, false);
            }
        }
        catch ( IOException e ) {
            log.error("Failed to read class " + methodReference.getTypeName()); //$NON-NLS-1$
        }
    }


    /**
     * @return the state
     */
    public SerianalyzerState getState () {
        return this.state;
    }


    /**
     * @param initialRef
     * @param wantFixedType
     * @param wantSerializableOnly
     * @return a potentially more concrete return type for the method
     */
    public Type getImprovedReturnType ( MethodReference initialRef, boolean wantFixedType, boolean wantSerializableOnly ) {

        MethodReference ref = initialRef;
        boolean fixedType = wantFixedType;
        boolean serializableOnly = wantSerializableOnly;

        String tName = ref.getTypeName().toString();
        if ( tName.endsWith("[]") && "clone".equals(ref.getMethod()) ) { //$NON-NLS-1$ //$NON-NLS-2$
            return Type.getType("L" + tName.replace('.', '/') + ";"); //$NON-NLS-1$ //$NON-NLS-2$
        }

        MethodReference c = ref.comparable();
        if ( this.state.getCheckedReturnType().contains(c) ) {
            return this.state.getReturnTypes().get(c);
        }

        this.state.getCheckedReturnType().add(c);

        Type fixedRetType = this.input.getConfig().getFixedReturnType(c);
        if ( fixedRetType != null ) {
            this.state.getReturnTypes().put(c, fixedRetType);
            return fixedRetType;
        }

        if ( this.input.getConfig().restrictToSerializable(ref) ) {
            serializableOnly = true;
        }

        DotName overrideType = this.input.getConfig().getFixedType(ref);
        if ( overrideType != null ) {
            fixedType = true;
            ref = ref.adaptToType(overrideType);
        }

        return doGetImprovedReturnType(ref, fixedType, serializableOnly, c);
    }


    /**
     * @param ref
     * @param fixedType
     * @param serializableOnly
     * @param c
     * @return
     */
    private Type doGetImprovedReturnType ( MethodReference ref, boolean fixedType, boolean serializableOnly, MethodReference c ) {
        Collection<ClassInfo> impls = findImplementors(c, fixedType, serializableOnly, false);

        if ( impls.isEmpty() ) {
            log.trace("No implementations found for " + c); //$NON-NLS-1$
            return null;
        }

        Set<Type> implTypes = new HashSet<>();
        boolean allFound = checkForReturnTypes(c, impls, implTypes);
        if ( allFound && !implTypes.isEmpty() ) {
            if ( implTypes.size() == 1 ) {
                Type t = implTypes.iterator().next();
                try {
                    foundImprovedReturnType(c, t, Type.getReturnType(ref.getSignature()));
                    return t;
                }
                catch ( SerianalyzerException e ) {
                    log.error("Incompatible type found", e); //$NON-NLS-1$
                }
            }
            else {
                if ( log.isDebugEnabled() ) {
                    log.debug("Multiple return types found for " + ref + ": " + implTypes); //$NON-NLS-1$ //$NON-NLS-2$
                }
                this.getState().getBench().multiReturnTypes();
            }
        }

        return null;
    }


    /**
     * @param c
     * @param impls
     * @param implTypes
     * @return
     */
    private boolean checkForReturnTypes ( MethodReference c, Collection<ClassInfo> impls, Set<Type> implTypes ) {
        boolean allFound = true;
        for ( ClassInfo impl : impls ) {
            boolean found = TypeUtil.implementsMethod(c, impl);
            if ( !found ) {
                continue;
            }

            MethodReference e = c.adaptToType(impl.name());
            try {
                if ( !this.state.getCheckedReturnType().contains(e) ) {
                    this.state.getCheckedReturnType().add(e);
                    doCheckMethod(e);
                    Type type = this.state.getReturnTypes().get(e);
                    if ( type != null ) {
                        implTypes.add(type);
                    }
                    else {
                        return false;
                    }
                }
            }
            catch ( SerianalyzerException e1 ) {
                log.warn("Failed to check method", e1); //$NON-NLS-1$
            }
        }
        return allFound;
    }


    /**
     * @param ref
     * @param retType
     */
    public void instantiable ( MethodReference ref, Type retType ) {
        if ( this.input.getConfig().isWhitelisted(ref) ) {
            return;
        }
        if ( retType.getSort() == Type.OBJECT ) {
            DotName typeName = DotName.createSimple(retType.getClassName());
            ClassInfo classByName = this.input.getIndex().getClassByName(typeName);
            if ( classByName != null ) {
                if ( !"java.lang.Object".equals(retType.getClassName()) && !TypeUtil.isSerializable(this.input.getIndex(), classByName) && ( classByName.flags() & Modifier.INTERFACE ) == 0 ) { //$NON-NLS-1$
                    this.state.trackInstantiable(typeName, ref);
                }
            }
        }
    }


    /**
     * @param ref
     */
    public void putstatic ( MethodReference ref ) {
        MethodReference comparable = ref.comparable();
        if ( !this.input.getConfig().getStaticPutWhitelist().contains(comparable) ) {
            this.state.getStaticPuts().add(comparable);
        }

    }

}
