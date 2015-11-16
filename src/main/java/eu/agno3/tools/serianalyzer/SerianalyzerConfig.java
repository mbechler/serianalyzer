/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 12.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.jboss.jandex.DotName;
import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
@SuppressWarnings ( "nls" )
public class SerianalyzerConfig {

    private static final Logger log = Logger.getLogger(SerianalyzerConfig.class);

    private boolean useHeuristics = true;
    private final Set<MethodReference> nativeWhitelist = new HashSet<>();
    private final Set<MethodReference> callWhitelist = new HashSet<>();
    private final Set<MethodReference> untaintReturn = new HashSet<>();
    private final Set<MethodReference> staticPutWhiteList = new HashSet<>();

    private final Set<String> ignorePkg = new HashSet<>(Arrays.asList(
        "java.awt.",
        "sun.awt.",
        "javax.swing.",
        "com.sun.java.swing.",
        "jdk.nashorn.internal."));

    private boolean dumpInstantiationInfo;

    private File restoreFrom;

    private File saveTo;


    private static final void whitelist ( Set<MethodReference> wl, String method ) {
        boolean stat = false;
        int methSep;
        if ( method.contains("::") ) {
            methSep = method.indexOf(':');
            stat = true;
        }
        else {
            methSep = method.indexOf("->");
        }

        if ( methSep < 0 ) {
            throw new IllegalArgumentException("Invalid line " + method);
        }

        int sigStart = method.indexOf('[');
        int sigEnd = method.indexOf(']');
        if ( sigStart < 0 || sigEnd < 0 ) {
            throw new IllegalArgumentException("Invalid line " + method);
        }

        String sig = method.substring(sigStart + 1, sigEnd);
        String clname = method.substring(0, methSep);
        String mname = method.substring(methSep + 2, sigStart - 1).trim();

        DotName dn = DotName.createSimple(clname);

        wl.add(new MethodReference(dn, false, mname, stat, sig));
    }


    private final void nw ( String method ) {
        whitelist(this.nativeWhitelist, method);
    }


    private final void cw ( String method ) {
        whitelist(this.callWhitelist, method);
    }


    private final void spw ( String method ) {
        whitelist(this.staticPutWhiteList, method);
    }


    private final void ur ( String method ) {
        whitelist(this.untaintReturn, method);
    }


    /**
     * @param i
     * @throws IOException
     */
    public final void readFile ( InputStream i ) throws IOException {
        try ( InputStreamReader isr = new InputStreamReader(i, "UTF-8");
              BufferedReader r = new BufferedReader(isr) ) {
            String line;
            while ( ( line = r.readLine() ) != null ) {
                if ( line.trim().isEmpty() ) {
                    continue;
                }
                switch ( line.charAt(0) ) {
                case '#':
                    continue;
                case 'N':
                    nw(line.substring(1).trim());
                    continue;
                case 'C':
                    cw(line.substring(1).trim());
                    continue;
                case 'S':
                    spw(line.substring(1).trim());
                    continue;
                case 'U':
                    ur(line.substring(1).trim());
                    continue;
                case 'P':
                    this.ignorePkg.add(line.substring(1).trim());
                    continue;
                default:
                    log.warn("Unrecognized line " + line);

                }
            }
        }
    }


    /**
     * @param noHeuristics
     * @param dumpInstantiationInfo
     */
    public SerianalyzerConfig ( boolean noHeuristics, boolean dumpInstantiationInfo ) {
        this.dumpInstantiationInfo = dumpInstantiationInfo;
        this.useHeuristics = !noHeuristics;
    }


    /**
     * @param ref
     * @return whether the method call is whitelisted
     */
    public boolean isWhitelisted ( MethodReference ref ) {

        if ( ref.getTypeName().toString().endsWith("[]") && "clone".equals(ref.getMethod()) ) { //$NON-NLS-1$ //$NON-NLS-2$
            return true;
        }

        String className = ref.getTypeName().toString();
        if ( ref.getTargetType() != null ) {
            className = ref.getTargetType().getClassName();
        }
        if ( isWhitelistedClass(className) ) {
            return true;
        }

        if ( this.callWhitelist.contains(ref.comparable()) ) {
            return true;
        }

        return false;
    }


    /**
     * @param r
     * @return whether the method return should be untainted
     */
    public boolean isUntaintReturn ( MethodReference r ) {
        return this.untaintReturn.contains(r.comparable());
    }


    /**
     * @param className
     * @return whether the class is whitelisted
     */
    public boolean isWhitelistedClass ( String className ) {
        for ( String pkg : this.ignorePkg ) {
            if ( className.startsWith(pkg) ) {
                return true;
            }
        }
        return false;
    }


    /**
     * @param methodReference
     * @return an target type to fix for the reference
     */
    public DotName getFixedType ( MethodReference methodReference ) {
        if ( this.useHeuristics && "java.io.ObjectInput".equals(methodReference.getTypeName().toString()) ) {
            return DotName.createSimple("java.io.ObjectInputStream");
        }
        else if ( this.useHeuristics && "java.io.ObjectInputStream".equals(methodReference.getTypeName().toString()) ) { //$NON-NLS-1$
            return methodReference.getTypeName();
        }
        return null;
    }


    /**
     * @return the useHeuristics
     */
    public boolean isUseHeuristics () {
        return this.useHeuristics;
    }


    /**
     * @return the dumpInstantiationInfo
     */
    public boolean isDumpInstantiationInfo () {
        return this.dumpInstantiationInfo;
    }


    /**
     * @param methodReference
     * @return whether the type should be restricted to serializable types
     */
    public boolean restrictToSerializable ( MethodReference methodReference ) {

        if ( this.useHeuristics && "java.lang.Runnable".equals(methodReference.getTypeName().toString()) ) {
            return true;
        }

        if ( this.useHeuristics && "java.lang.Enumeration".equals(methodReference.getTypeName().toString()) ) {
            return true;
        }

        return false;
    }


    /**
     * @return the static put method whitelist
     */
    public Set<MethodReference> getStaticPutWhitelist () {
        return Collections.unmodifiableSet(this.staticPutWhiteList);
    }


    /**
     * @return the native method whitelist
     */
    public Collection<? extends MethodReference> getNativeWhiteList () {
        return Collections.unmodifiableSet(this.nativeWhitelist);
    }


    /**
     * @param c
     * @return a fixed return type for the method
     */
    public Type getFixedReturnType ( MethodReference c ) {
        // TODO Auto-generated method stub
        return null;
    }


    /**
     * @return whether to ignore not found types
     */
    public boolean isIgnoreNonFound () {
        return true;
    }


    /**
     * @return file to save state to
     */
    public File getSaveTo () {
        return this.saveTo;
    }


    /**
     * @param saveTo
     *            the saveTo to set
     */
    public void setSaveTo ( File saveTo ) {
        this.saveTo = saveTo;
    }


    /**
     * @return file to restore state from
     */
    public File getRestoreFrom () {
        return this.restoreFrom;
    }


    /**
     * @param restoreFrom
     *            the restoreFrom to set
     */
    public void setRestoreFrom ( File restoreFrom ) {
        this.restoreFrom = restoreFrom;
    }


    /**
     * @return the maximum numer of call traces to output per instance
     */
    public int getMaxDisplayDumps () {
        return 5;
    }

}
