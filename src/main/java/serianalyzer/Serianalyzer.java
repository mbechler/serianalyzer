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
 * Created: 11.11.2015 by mbechler
 */
package serianalyzer;


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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
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

    private static final long OUTPUT_EVERY = 10000;

    private SerianalyzerInput input;
    private SerianalyzerState state;

    private Map<String, Boolean> serializableCache = new HashMap<>();

    private long lastOutput = 0;


    /**
     * @param input
     */
    public Serianalyzer ( SerianalyzerInput input ) {
        this.input = input;
        this.state = new SerianalyzerState();
    }


    /**
     * @return whether any bad instances were found
     * @throws SerianalyzerException
     * 
     */
    public boolean analyze () throws SerianalyzerException {
        return restoreOrRunAnalysis();
    }


    /**
     * @return
     * @throws SerianalyzerException
     * 
     */
    private boolean restoreOrRunAnalysis () throws SerianalyzerException {
        boolean foundAny;
        if ( this.input.getConfig().getRestoreFrom() != null ) {
            restore();
            foundAny = filterAndDump();
            save();
        }
        else {
            this.lastOutput = System.currentTimeMillis();
            runAnalysis();
            save();
            log.info(String.format("Found a total %d method calls reachable", this.state.getTotalKnownCount())); //$NON-NLS-1$
            log.info(String.format("Found a total %d native method initially reachable", this.state.getNativeMethods().size())); //$NON-NLS-1$
            log.info(String.format("Found a total %d safe methods", this.state.getSafe().size())); //$NON-NLS-1$
            foundAny = filterAndDump();
        }
        return foundAny;
    }


    /**
     * @return
     * 
     */
    private boolean filterAndDump () {
        prefilterMethods();
        log.info(String.format("Found a total %d native methods remaining", this.state.getNativeMethods().size())); //$NON-NLS-1$
        List<MethodReference> dump = new ArrayList<>(this.state.getNativeMethods());
        Collections.sort(dump, new MethodReferenceComparator());

        Set<DotName> usedInstantiable = new HashSet<>();
        long stPuts = dumpMethodCalls(this.state.getStaticPuts(), usedInstantiable, "Potentially unsafe static put in ", 1).size(); //$NON-NLS-1$
        log.info(String.format("Found %d potentially unsafe static puts", stPuts)); //$NON-NLS-1$

        Collection<MethodReference> nonWhitelist = dumpMethodCalls(
            dump,
            usedInstantiable,
            "Potentially unsafe native call ", //$NON-NLS-1$
            this.input.getConfig().getMaxDisplayDumps());
        log.info(String.format("Found %d non-whitelisted native methods", nonWhitelist.size())); //$NON-NLS-1$

        for ( MethodReference ref : nonWhitelist ) {
            log.info(ref);
        }

        if ( this.input.getConfig().isDumpInstantiationInfo() ) {
            dumpInstantiable(usedInstantiable);
        }

        this.state.getBench().dump();

        return nonWhitelist.size() > 0 || stPuts > 0;
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
            log.info("Loading state..."); //$NON-NLS-1$
            try ( FileInputStream fis = new FileInputStream(this.input.getConfig().getRestoreFrom());
                  ObjectInputStream ois = new ObjectInputStream(fis) ) {
                this.state = (SerianalyzerState) ois.readObject();
            }
            catch (
                IOException |
                ClassNotFoundException e ) {
                throw new SerianalyzerException("Failed to restore state", e); //$NON-NLS-1$
            }
            log.info("Loaded state"); //$NON-NLS-1$
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
            this.state.trackKnown(method);
            doCheckMethod(method);
        }
    }


    /**
     * 
     */
    private void prefilterMethods () {
        log.info("Running filtering with heuristics " + ( this.input.getConfig().isUseHeuristics() ? "ENABLED" : "DISABLED" )); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
        removeIgnoreTaint(this.state.getSafe(), this.state.getNativeMethods());
        this.state.getSafe().addAll(this.input.getConfig().getNativeWhiteList());
        this.state.getNativeMethods().removeAll(this.input.getConfig().getNativeWhiteList());

        for ( MethodReference s : this.state.getSafe() ) {
            removeSafeCalls(s);
        }

        log.info(String.format("Remaining methods %d", this.state.getTotalKnownCount())); //$NON-NLS-1$
        Set<MethodReference> toRemove = new HashSet<>();

        boolean anyChanged = true;
        int i = 0;
        while ( anyChanged ) {
            i++;
            log.info("Filtering: iteration " + i + "..."); //$NON-NLS-1$ //$NON-NLS-2$
            anyChanged = false;
            anyChanged |= removeUninstantiable();

            Set<MethodReference> known = new HashSet<>(this.state.getMethodCallers().keySet());
            for ( MethodReference kn : known ) {
                anyChanged |= removeNonReachable(kn, this.state.getInitial(), toRemove);
            }
            anyChanged |= this.state.removeAllKnown(toRemove);
            anyChanged |= this.state.getStaticPuts().removeAll(toRemove);
            log.info(String.format("Remaining methods %d", this.state.getTotalKnownCount())); //$NON-NLS-1$
            log.info(String.format("Remaining instantiable types %d", this.state.getInstantiableTypes().size())); //$NON-NLS-1$
            anyChanged |= removeIgnoreTaint(this.state.getNativeMethods(), toRemove);
            toRemove.clear();
        }

        log.info("Finished filtering"); //$NON-NLS-1$
        System.out.flush();
        System.err.flush();
    }


    /**
     * @return
     * 
     */
    private boolean removeUninstantiable () {
        Set<String> toRemove = new HashSet<>();
        Map<String, Boolean> recursionCache = new HashMap<>();
        for ( String typeName : this.state.getInstantiableTypes() ) {
            if ( checkAllRecursive(typeName, new HashSet<>(), recursionCache) ) {
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
    private Collection<MethodReference> dumpMethodCalls ( Collection<MethodReference> dump, Set<DotName> usedInstantiable, String msg,
            int maxDumps ) {
        Collection<MethodReference> nonWhitelist = new ArrayList<>();
        for ( MethodReference cal : dump ) {
            cal = cal.comparable();

            if ( this.input.getConfig().isWhitelisted(cal) ) {
                continue;
            }

            Set<MethodReference> callers = this.state.getMethodCallers().get(cal);
            if ( callers == null || callers.isEmpty() ) {
                continue;
            }

            if ( !dumpBacktraces(cal, this.state.getInitial(), usedInstantiable, "", maxDumps) ) { //$NON-NLS-1$
                continue;
            }
            System.out.flush();
            System.err.flush();
            System.err.println(msg + cal);
            nonWhitelist.add(cal);
        }
        return nonWhitelist;
    }


    private void dumpInstantiable ( Set<DotName> usedInstantiable ) {
        System.out.flush();
        System.err.flush();
        System.out.println(String.format("Used %d non-serializable instantiable types: ", usedInstantiable.size())); //$NON-NLS-1$

        for ( DotName name : usedInstantiable ) {
            if ( !this.state.getInstantiableTypes().contains(name.toString()) ) {
                continue;
            }
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
    private boolean dumpBacktraces ( Queue<List<MethodReference>> toVisit, Set<MethodReference> targets, Set<DotName> usedInstantiable, String prefix,
            Set<MethodReference> visited, int initialLimit ) {

        int limit = initialLimit;

        boolean anyFound = false;
        while ( !toVisit.isEmpty() ) {
            List<MethodReference> p = toVisit.poll();
            MethodReference r = p.get(p.size() - 1);

            if ( targets.contains(r) && !this.state.getMaximumTaintStatus(r).isParameterTainted(0) ) {
                if ( this.input.getConfig().isWhitelisted(r) ) {
                    continue;
                }

                if ( "<clinit>".equals(r.getMethod()) ) { //$NON-NLS-1$
                    continue;
                }

                limit--;

                for ( MethodReference elem : p ) {
                    System.out.print(prefix + this.state.getMaximumTaintStatus(elem));
                    DotName tn = elem.getTypeName();
                    if ( this.isTypeSerializable(getIndex(), elem.getTypeNameString()) ) {
                        System.out.println(" serializable"); //$NON-NLS-1$
                    }
                    else if ( this.state.isInstantiable(elem) ) {
                        usedInstantiable.add(tn);
                        System.out.println(" instantiable"); //$NON-NLS-1$
                    }
                    else {
                        System.out.println();
                    }
                }
                System.out.println();
                System.out.flush();
                System.err.flush();
                anyFound = true;
                if ( initialLimit != 1 && limit <= 0 ) {

                    System.out.println();
                    System.out.println("There can be more paths..."); //$NON-NLS-1$
                    System.out.println();

                    return true;
                }
                continue;
            }

            Set<MethodReference> set = this.state.getMethodCallers().get(r);

            if ( set != null && !set.isEmpty() ) {
                for ( MethodReference ref : set ) {
                    if ( !visited.contains(ref) && !r.equals(ref) ) {
                        List<MethodReference> np = new ArrayList<>(p);
                        // if ( filterPath(np) ) {
                        // this.getState().getBench().heuristicFilter();
                        // continue;
                        // }
                        np.add(ref);
                        toVisit.add(np);
                        visited.add(ref);
                    }
                }
            }
            else if ( log.isDebugEnabled() ) {
                log.debug("No callers found for " + r); //$NON-NLS-1$
            }
        }

        return anyFound;
    }


    /**
     * @param cal
     * @param i
     */
    private boolean isReachable ( MethodReference start, Set<MethodReference> targets ) {
        MethodReference comparable = start.comparable();
        List<MethodReference> rootPath = new ArrayList<>(Arrays.asList(comparable));
        Queue<List<MethodReference>> toVisit = new LinkedList<>(Arrays.asList(rootPath));
        Set<MethodReference> visited = new HashSet<>();

        while ( !toVisit.isEmpty() ) {
            List<MethodReference> p = toVisit.poll();
            MethodReference r = p.get(p.size() - 1);

            if ( targets.contains(r) ) {
                return true;
            }

            Set<MethodReference> set = this.state.getMethodCallers().get(r);

            if ( set != null && !set.isEmpty() ) {
                for ( MethodReference ref : set ) {
                    if ( !visited.contains(ref) && !r.equals(ref) ) {
                        List<MethodReference> np = new ArrayList<>(p);
                        np.add(ref);
                        toVisit.add(np);
                        visited.add(ref);
                    }
                }
            }
        }

        return false;
    }


    /**
     * @param string
     * @param typeName
     */
    private void traceInstantiation ( String prefix, DotName typeName, Set<MethodReference> found ) {

        if ( checkAllRecursive(typeName.toString(), new HashSet<>(), new HashMap<>()) ) {
            log.warn("All instantiations are recursive for " + typeName); //$NON-NLS-1$
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
                System.out.print(prefix + "-> " + this.state.getMaximumTaintStatus(comparable)); //$NON-NLS-1$
                boolean nonSerializable = !this.isTypeSerializable(getIndex(), r.getTypeNameString());
                Set<MethodReference> callers = this.state.getMethodCallers().get(comparable);

                if ( !nonSerializable && ( callers == null || callers.isEmpty() ) ) {
                    log.warn("No callers found for " + typeName); //$NON-NLS-1$
                    continue;
                }

                if ( nonSerializable ) {
                    System.out.println();
                }
                else {
                    System.out.println(" serializable"); //$NON-NLS-1$
                }

                if ( !dumpBacktraces(comparable, this.state.getInitial(), new HashSet<>(), prefix + "   * ", 1) ) { //$NON-NLS-1$
                    if ( log.isDebugEnabled() ) {
                        log.debug("No paths found for " + comparable); //$NON-NLS-1$
                    }
                }

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
    private boolean checkAllRecursive ( String typeName, Set<String> visited, Map<String, Boolean> recursionCache ) {
        Set<MethodReference> i = this.state.getInstantiatedThrough().get(typeName);

        Logger cl = Logger.getLogger(this.getClass().getName() + "." + typeName); //$NON-NLS-1$

        if ( i == null || i.isEmpty() ) {
            log.warn("Instantiated through is empty " + typeName); //$NON-NLS-1$
            return this.input.getConfig().isFilterNonReachableInitializers();
        }

        if ( recursionCache.containsKey(typeName) ) {
            if ( cl.isDebugEnabled() ) {
                cl.debug("Cached " + typeName + " " + recursionCache.get(typeName)); //$NON-NLS-1$ //$NON-NLS-2$
            }
            return recursionCache.get(typeName);
        }

        if ( visited.contains(typeName) ) {
            if ( cl.isDebugEnabled() ) {
                cl.debug("Already visited " + typeName); //$NON-NLS-1$
            }
            return true;
        }

        Queue<String> toVisit = new LinkedList<>(Collections.singleton(typeName));
        visited.add(typeName);
        if ( cl.isTraceEnabled() ) {
            cl.trace("Checking " + typeName); //$NON-NLS-1$
        }
        while ( !toVisit.isEmpty() ) {
            String type = toVisit.poll();

            if ( this.isTypeSerializable(this.getIndex(), type) || this.input.getConfig().isConsiderInstantiable(type) ) {
                if ( cl.isDebugEnabled() ) {
                    cl.debug("Type is serializable/instatiable " + type); //$NON-NLS-1$
                }
                recursionCache.put(typeName, false);
                return false;
            }

            Set<MethodReference> set = this.state.getInstantiatedThrough().get(type);
            if ( set != null && !set.isEmpty() ) {
                if ( cl.isTraceEnabled() ) {
                    cl.trace(String.format("Checking %d instantiators for %s: %s", set.size(), type, set)); //$NON-NLS-1$
                }
                for ( MethodReference ref : set ) {
                    if ( !isReachable(ref, this.state.getInitial()) ) {
                        if ( cl.isDebugEnabled() ) {
                            cl.debug("Non reachable " + ref); //$NON-NLS-1$
                        }
                        continue;
                    }
                    Set<MethodReference> callers = this.state.getMethodCallers().get(ref.comparable());

                    if ( callers == null || callers.isEmpty() ) {
                        if ( cl.isDebugEnabled() ) {
                            cl.debug("No callers found for " + ref); //$NON-NLS-1$
                        }
                        continue;
                    }

                    if ( cl.isTraceEnabled() ) {
                        cl.trace("Callers for " + ref + " are " + callers); //$NON-NLS-1$ //$NON-NLS-2$
                    }

                    boolean delayReturnFalse = false;
                    for ( MethodReference c : callers ) {

                        String cType = c.getTypeNameString();

                        if ( visited.contains(cType) ) {
                            continue;
                        }

                        Set<String> types = new HashSet<>();

                        if ( c.isStatic() ) {
                            Set<MethodReference> origCallers = new HashSet<>();
                            resolveNonStaticCallers(c, origCallers, new HashSet<>());
                            for ( MethodReference oc : origCallers ) {
                                if ( !isReachable(oc, this.state.getInitial()) ) {
                                    if ( cl.isDebugEnabled() ) {
                                        cl.debug("Non reachable " + oc); //$NON-NLS-1$
                                    }
                                    continue;
                                }
                                if ( cl.isDebugEnabled() ) {
                                    cl.debug("Adding type for " + oc); //$NON-NLS-1$
                                }
                                types.add(oc.getTypeNameString());
                            }
                        }
                        else {
                            if ( !isReachable(c, this.state.getInitial()) ) {
                                if ( cl.isDebugEnabled() ) {
                                    cl.debug("Non reachable " + c); //$NON-NLS-1$
                                }
                                continue;
                            }
                            types.add(cType);
                        }

                        for ( String t : types ) {
                            if ( this.isTypeSerializable(this.getIndex(), t) || this.getState().isForcedInstantiable(t)
                                    || this.input.getConfig().isConsiderInstantiable(t) ) {
                                if ( cl.isDebugEnabled() ) {
                                    cl.debug("Instantiating type is serializable/instatiable " + t); //$NON-NLS-1$
                                }
                                recursionCache.put(typeName, false);
                                if ( cl.isDebugEnabled() ) {
                                    delayReturnFalse = true;
                                    continue;
                                }
                                return false;

                            }

                            if ( this.state.getInstantiableTypes().contains(t) ) {
                                if ( checkAllRecursive(t, visited, recursionCache) ) {
                                    if ( cl.isDebugEnabled() ) {
                                        cl.debug("Instantiating type is also recursive " + t); //$NON-NLS-1$
                                    }
                                    continue;
                                }
                                return false;
                            }

                            if ( cl.isDebugEnabled() ) {
                                cl.debug("Checking type " + t); //$NON-NLS-1$
                            }

                            if ( !visited.contains(t) ) {
                                toVisit.add(t);
                                visited.add(t);
                            }
                        }

                    }

                    if ( delayReturnFalse ) {
                        return false;
                    }
                }
            }
            else if ( cl.isDebugEnabled() ) {
                cl.debug("No instantiations found for " + type); //$NON-NLS-1$
            }
        }

        if ( cl.isDebugEnabled() ) {
            cl.debug("Only recursive instantiations " + typeName); //$NON-NLS-1$
            cl.debug("Visited types " + visited); //$NON-NLS-1$
        }
        recursionCache.put(typeName, true);
        return true;

    }


    /**
     * @param index
     * @param classByName
     * @return
     */
    private boolean isTypeSerializable ( Index index, String typeName ) {

        Boolean s = this.serializableCache.get(typeName);
        if ( s != null ) {
            return s;
        }
        ClassInfo classByName = index.getClassByName(DotName.createSimple(typeName));
        s = TypeUtil.isSerializable(index, classByName);
        this.serializableCache.put(typeName, s);
        return s;
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


    private boolean removeNonReachable ( MethodReference ref, Set<MethodReference> retainSet, Set<MethodReference> toRemove ) {
        MethodReference s = ref.comparable();
        if ( toRemove.contains(s) ) {
            return false;
        }

        if ( this.input.getConfig().isWhitelisted(s) ) {
            return this.state.remove(s, toRemove, RemovalReason.WHITELIST, this.input.getConfig());
        }

        if ( !retainSet.contains(s) && !"<clinit>".equals(s.getMethod()) //$NON-NLS-1$
                && ( this.state.getMethodCallers().get(s) == null || this.state.getMethodCallers().get(s).isEmpty() ) ) {
            return this.state.remove(s, toRemove, RemovalReason.NOCALLERS, this.input.getConfig());
        }

        if ( !this.input.getConfig().isUseHeuristics() ) {
            return false;
        }

        if ( ( s.isStatic() || this.isTypeSerializable(this.getIndex(), s.getTypeNameString()) || this.state.isInstantiable(s)
                || this.input.getConfig().isConsiderInstantiable(s.getTypeNameString()) ) ) {
            return false;
        }

        return this.state.remove(s, toRemove, RemovalReason.UNINSTATIABLE, this.input.getConfig());
    }


    /**
     * @param s
     */
    private void removeSafeCalls ( MethodReference ref ) {
        MethodReference s = ref.comparable();
        if ( !this.state.removeAllKnown(Collections.singleton(s)) ) {
            return;
        }

        Set<MethodReference> calls = this.state.getMethodCallers().get(s);
        if ( calls == null ) {
            return;
        }

        for ( MethodReference caller : calls ) {
            Set<MethodReference> callerCalls = this.state.getMethodCallees().get(caller);
            if ( callerCalls != null ) {
                Logger cl = Logger.getLogger(Serianalyzer.class.getName() + "." + s.getTypeNameString() + "." + s.getMethod()); //$NON-NLS-1$ //$NON-NLS-2$
                if ( "<init>".equals(s.getMethod()) ) { //$NON-NLS-1$
                    continue;
                }
                callerCalls.remove(s);
                if ( cl.isDebugEnabled() ) {
                    cl.debug(String.format("SAFE, removing call %s from %s, remaining calls %s", s, caller, callerCalls)); //$NON-NLS-1$
                }
                if ( callerCalls.isEmpty() ) {
                    cl.debug("Caller not longer has any calls"); //$NON-NLS-1$
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
        DotName dname = ci.name();
        String dnameString = dname.toString();
        try ( InputStream data = this.input.getClassData(dnameString) ) {
            if ( data == null ) {
                log.error("No class data for " + dname); //$NON-NLS-1$
                return;
            }
            boolean serializable = this.isTypeSerializable(this.getIndex(), dnameString);
            ClassReader cr = new ClassReader(data);
            if ( log.isTraceEnabled() ) {
                log.trace("Adding " + dnameString); //$NON-NLS-1$
            }
            SerianalyzerClassSerializationVisitor visitor = new SerianalyzerClassSerializationVisitor(this, dnameString, serializable);
            cr.accept(visitor, 0);
            if ( serializable ) {
                ClassInfo classByName = this.input.getIndex().getClassByName(ci.superName());
                if ( classByName == null ) {
                    log.error("Failed to locate super class " + ci.superName()); //$NON-NLS-1$
                    return;
                }
                checkClass(classByName);
            }
            else if ( !visitor.isFoundDefaultConstructor() && log.isTraceEnabled() ) {
                log.trace("No default constructor found in first non-serializable parent " + dname); //$NON-NLS-1$
            }
        }
        catch ( IOException e ) {
            throw new SerianalyzerException("Failed to read class data" + dname, e); //$NON-NLS-1$
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

        Logger cl = Logger.getLogger(Serianalyzer.class.getName() + "." + initialRef.getTypeNameString() + "." + initialRef.getMethod()); //$NON-NLS-1$ //$NON-NLS-2$

        if ( cl.isTraceEnabled() ) {
            log.trace("Adding call " + initialRef + " with caller " + cal); //$NON-NLS-1$ //$NON-NLS-2$
        }

        boolean fixedType = wantFixedType;
        MethodReference methodReference = initialRef;
        MethodReference comparable = methodReference.comparable();
        boolean serializableOnly = wantSerializableOnly;

        if ( this.input.getConfig().restrictToSerializable(methodReference) ) {
            serializableOnly = true;
        }

        DotName overrideType = this.input.getConfig().getFixedType(methodReference);
        if ( overrideType != null ) {
            fixedType = true;
            methodReference = methodReference.adaptToType(overrideType);
        }

        if ( "<init>".equals(methodReference.getMethod()) && initialRef.isCalleeTainted() ) { //$NON-NLS-1$
            this.state.trackInstantiable(methodReference.getTypeNameString(), methodReference, this.input.getConfig(), false);
        }

        if ( methodReference.getArgumentTypes() != null && this.state.countKnown(comparable) > this.input.getConfig().getMaxChecksPerReference() ) {
            // also drops the argument types
            this.state.getBench().reachedMethodLimit();
            Type tgtType = methodReference.getTargetType();
            methodReference = methodReference.fullTaint();
            methodReference.setTargetType(tgtType);
        }

        this.state.traceCalls(methodReference, cal);

        if ( isImplied(cl, comparable, initialRef, methodReference) ) {
            if ( cl.isTraceEnabled() ) {
                cl.trace("Implied " + methodReference); //$NON-NLS-1$
            }
            this.getState().getBench().impliedCall();
            return false;
        }

        if ( this.input.getConfig().isWhitelisted(methodReference) ) {
            if ( cl.isDebugEnabled() ) {
                cl.debug("Whitelisted method " + methodReference); //$NON-NLS-1$
            }
            return false;
        }

        if ( this.state.isKnown(methodReference) ) {
            if ( cl.isTraceEnabled() ) {
                cl.trace("Method already found " + methodReference); //$NON-NLS-1$
            }
            return true;
        }

        if ( this.state.getSafe().contains(comparable) ) {
            if ( cl.isDebugEnabled() ) {
                cl.debug("Is safe " + comparable); //$NON-NLS-1$
            }
            return false;
        }

        this.state.trackKnown(methodReference);
        Collection<ClassInfo> impls = findImplementors(methodReference, fixedType, serializableOnly, true);

        if ( impls.isEmpty() ) {
            if ( log.isDebugEnabled() ) {
                cl.debug("No implementations found for " + methodReference + //$NON-NLS-1$
                        " fixed " + fixedType + //$NON-NLS-1$
                        " serializable " + serializableOnly); //$NON-NLS-1$
            }
            ClassInfo classByName = this.getIndex().getClassByName(methodReference.getTypeName());
            if ( classByName != null ) {
                impls = Collections.singleton(classByName);
            }
            else if ( !this.getConfig().isIgnoreNonFound() ) {
                log.warn("Class not found " + methodReference.getTypeNameString()); //$NON-NLS-1$
            }
        }

        if ( cl.isTraceEnabled() ) {
            Set<String> implNames = new HashSet<>();
            for ( ClassInfo classInfo : impls ) {
                implNames.add(classInfo.name().toString());
            }
            cl.trace("Found implementations " + implNames + //$NON-NLS-1$
                    " fixed: " + fixedType + //$NON-NLS-1$
                    " serializable: " + serializableOnly); //$NON-NLS-1$
        }

        boolean anyFound = false;
        for ( ClassInfo impl : impls ) {
            MethodReference e = methodReference.adaptToType(impl.name());
            TypeUtil.checkReferenceTyping(this.input.getIndex(), this.input.getConfig().isIgnoreNonFound(), e);
            this.state.traceCalls(e, cal);
            this.state.trackKnown(e);
            this.state.getToCheck().add(e);
            anyFound = true;
        }

        if ( !anyFound && cl.isDebugEnabled() ) {
            cl.debug("No usable implementation found for " + methodReference); //$NON-NLS-1$
        }

        return anyFound;

    }


    /**
     * @param comparable
     * @param methodReference
     * @return
     */
    private boolean isImplied ( Logger cl, MethodReference comparable, MethodReference actual, MethodReference methodReference ) {
        Set<MethodReference> alreadyKnown = this.state.getAlreadyKnown(comparable);
        for ( MethodReference ref : alreadyKnown ) {
            if ( ref.implies(methodReference) ) {
                if ( cl.isTraceEnabled() ) {
                    cl.trace(actual + " implied by " + methodReference); //$NON-NLS-1$
                }
                return true;
            }
        }

        return false;
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
        return TypeUtil.findImplementors(
            methodReference,
            this.input.getConfig().isIgnoreNonFound(),
            fixedType,
            serializableOnly,
            doBench ? this.getState().getBench() : null,
            getIndex());

    }


    /**
     * @param method
     * @throws SerianalyzerException
     */
    private void doCheckMethod ( MethodReference methodReference ) throws SerianalyzerException {

        Logger cl = Logger.getLogger(Serianalyzer.class.getName() + "." + methodReference.getTypeNameString()); //$NON-NLS-1$

        if ( cl.isTraceEnabled() ) {
            cl.trace(String.format("Checking reference %s", methodReference)); //$NON-NLS-1$
        }

        long currentTimeMillis = System.currentTimeMillis();
        if ( currentTimeMillis - this.lastOutput > OUTPUT_EVERY ) {
            log.info("Currently to check " + this.getState().getToCheck().size()); //$NON-NLS-1$
            log.info("Sample " + methodReference); //$NON-NLS-1$
            this.lastOutput = currentTimeMillis;
        }

        try ( InputStream data = this.input.getClassData(methodReference.getTypeNameString()) ) {
            if ( data == null ) {
                cl.error("No class data for " + methodReference.getTypeNameString()); //$NON-NLS-1$
                return;
            }

            if ( this.input.getConfig().isWhitelisted(methodReference) ) {
                if ( cl.isDebugEnabled() ) {
                    cl.debug("Is whitelisted " + methodReference); //$NON-NLS-1$
                }
                return;
            }

            ClassReader cr = new ClassReader(data);
            SerianalyzerClassMethodVisitor visitor = new SerianalyzerClassMethodVisitor(this, methodReference, methodReference.getTypeNameString());
            cr.accept(visitor, 0);

            Set<MethodReference> callers = this.state.getMethodCallers().get(methodReference.comparable());

            if ( !visitor.isFound() ) {
                if ( cl.isTraceEnabled() ) {
                    cl.trace("Not found " + methodReference); //$NON-NLS-1$
                }

                boolean found = doCheckInSuperClasses(methodReference, cl, callers);

                if ( !found ) {
                    log.debug("Method not found in superclasses " + methodReference); //$NON-NLS-1$
                }

                found = doCheckInInterfaces(methodReference, cl, callers);

                if ( !found ) {
                    log.debug("Method not found " + methodReference); //$NON-NLS-1$
                }
            }
        }
        catch ( IOException e ) {
            log.error("Failed to read class " + methodReference.getTypeName()); //$NON-NLS-1$
        }
    }


    /**
     * @param methodReference
     * @param cl
     * @param callers
     * @return
     * @throws IOException
     */
    private boolean doCheckInInterfaces ( MethodReference methodReference, Logger cl, Set<MethodReference> callers ) throws IOException {
        ClassInfo cur = this.input.getIndex().getClassByName(methodReference.getTypeName());
        while ( cur != null ) {
            // seems we cannot really determine whether there is a default method
            // probably jandex is missing a flag for this
            List<ClassInfo> checkInterfaces = TypeUtil.checkInterfaces(getIndex(), methodReference, cur);
            if ( checkInterfaces != null && !checkInterfaces.isEmpty() ) {
                if ( checkInterfaces.size() > 1 ) {
                    log.error("Multiple default implementations found " + checkInterfaces); //$NON-NLS-1$
                }
                MethodReference intfRef = methodReference.adaptToType(checkInterfaces.get(0).name());
                this.state.traceCalls(intfRef, callers);
                doCheckClassInternal(cl, intfRef);
                return true;
            }

            cur = getIndex().getClassByName(cur.superName());
        }
        return false;
    }


    /**
     * @param methodReference
     * @param cl
     * @param callers
     * @return
     * @throws IOException
     */
    private boolean doCheckInSuperClasses ( MethodReference methodReference, Logger cl, Set<MethodReference> callers ) throws IOException {
        DotName dn = methodReference.getTypeName();
        do {
            ClassInfo ci = this.input.getIndex().getClassByName(dn);
            if ( ci == null || "java.lang.Object".equals(dn.toString()) ) { //$NON-NLS-1$
                break;
            }

            DotName superName;
            if ( ci.superName() == null ) {
                superName = DotName.createSimple("java.lang.Object"); //$NON-NLS-1$
            }
            else {
                superName = ci.superName();
            }
            MethodReference superRef = methodReference.adaptToType(superName);

            if ( TypeUtil.implementsMethod(superRef, ci) ) {
                this.state.traceCalls(superRef, callers);
                return doCheckClassInternal(cl, superRef);
            }
            dn = superName;
        }
        while ( true );
        return false;
    }


    /**
     * @param cl
     * @param superRef
     * @return
     * @throws IOException
     */
    private boolean doCheckClassInternal ( Logger cl, MethodReference superRef ) throws IOException {
        SerianalyzerClassMethodVisitor visitor;
        try ( InputStream superData = this.input.getClassData(superRef.getTypeNameString()) ) {
            if ( superData == null ) {
                cl.error("No class data for " + superRef.getTypeNameString()); //$NON-NLS-1$
                return false;
            }

            ClassReader sr = new ClassReader(superData);
            visitor = new SerianalyzerClassMethodVisitor(this, superRef, superRef.getTypeNameString());
            sr.accept(visitor, 0);
            if ( visitor.isFound() ) {
                return true;
            }

        }

        return false;
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

        String tName = ref.getTypeNameString();
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
        boolean allFound = checkForReturnTypes(ref, impls, implTypes);
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

        if ( c.getArgumentTypes() != null ) {
            return false;
        }

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
            String className = retType.getClassName();
            DotName typeName = DotName.createSimple(className);
            ClassInfo classByName = this.input.getIndex().getClassByName(typeName);
            if ( classByName != null ) {
                if ( !"java.lang.Object".equals(className) && !this.isTypeSerializable(this.getIndex(), className) ) { //$NON-NLS-1$
                    if ( ( Modifier.isInterface(classByName.flags()) || Modifier.isAbstract(classByName.flags()) )
                            && this.input.getConfig().isNastyBase(className) ) {
                        return;
                    }

                    for ( DotName ifname : classByName.interfaceNames() ) {
                        String ifStr = ifname.toString();
                        if ( !this.input.getConfig().isNastyBase(ifStr) ) {
                            this.state.trackInstantiable(ifStr, ref, this.input.getConfig(), false);
                        }
                    }

                    this.state.trackInstantiable(className, ref, this.input.getConfig(), false);
                }
            }
        }
    }


    /**
     * @param ref
     */
    public void putstatic ( MethodReference ref ) {
        if ( !this.input.getConfig().isCheckStaticPuts() ) {
            return;
        }
        MethodReference comparable = ref.comparable();
        if ( !this.input.getConfig().getStaticPutWhitelist().contains(comparable) ) {
            this.state.getStaticPuts().add(comparable);
        }

    }

}
