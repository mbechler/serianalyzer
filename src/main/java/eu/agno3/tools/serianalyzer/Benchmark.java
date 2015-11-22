/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 14.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.Serializable;

import org.apache.log4j.Logger;


/**
 * @author mbechler
 *
 */
public class Benchmark implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -3560731346727327463L;

    private static final Logger log = Logger.getLogger(Benchmark.class);

    private int taintedCall;
    private int untaintedCall;

    private int taintedByMissingArgs;

    private int unboundedInterfaceCalls;

    private int improvedReturnTypes;

    private int nonImprovedReturnTypes;

    private int heuristicFilter;

    private int backwardJumps;

    private int unhandledLambdas;

    private int multiReturnTypes;

    private int impliedCalls;


    /**
     * 
     */
    public void taintedCall () {
        this.taintedCall++;
    }


    /**
     * 
     */
    public void untaintedCall () {
        this.untaintedCall++;
    }


    /**
     * 
     */
    public void taintedByMissingArgs () {
        this.taintedByMissingArgs++;
    }


    /**
     * 
     */
    public void improvedReturnType () {
        this.improvedReturnTypes++;
    }


    /**
     * 
     */
    public void nonImprovedReturnType () {
        this.nonImprovedReturnTypes++;
    }


    /**
     * 
     */
    public void unboundedInterfaceCalls () {
        this.unboundedInterfaceCalls++;
    }


    /**
     * 
     */
    public void heuristicFilter () {
        this.heuristicFilter++;
    }


    /**
     * 
     */
    public void backwardJump () {
        this.backwardJumps++;
    }


    /**
     * 
     */
    public void unhandledLambda () {
        this.unhandledLambdas++;
    }


    /**
     * 
     */
    public void multiReturnTypes () {
        this.multiReturnTypes++;
    }


    /**
     * 
     */
    public void impliedCall () {
        this.impliedCalls++;
    }


    /**
     * 
     */
    public void dump () {
        log.info("Total calls " + ( this.taintedCall + this.untaintedCall )); //$NON-NLS-1$
        log.info("Tainted calls " + this.taintedCall); //$NON-NLS-1$
        log.info("Calls tainted by unknown arguments " + this.taintedByMissingArgs); //$NON-NLS-1$
        log.info("Implied calls " + this.impliedCalls); //$NON-NLS-1$
        log.info("Untainted calls " + this.untaintedCall); //$NON-NLS-1$
        log.info("Backward jumps " + this.backwardJumps); //$NON-NLS-1$
        log.info("Improved return types " + this.improvedReturnTypes); //$NON-NLS-1$
        log.info("Return type analysis unsuccessful " + this.nonImprovedReturnTypes); //$NON-NLS-1$
        log.info("Return type analysis yielded multiple " + this.multiReturnTypes); //$NON-NLS-1$
        log.info("Lambdas for which type analysis was unsuccessful " + this.unhandledLambdas); //$NON-NLS-1$
        log.info("Unbounded interface calls " + this.unboundedInterfaceCalls); //$NON-NLS-1$
        log.info("Heuristically filtered " + this.heuristicFilter); //$NON-NLS-1$
        log.info("Memory used " + ( Runtime.getRuntime().totalMemory() / 1024 / 1024 ) + "MB"); //$NON-NLS-1$ //$NON-NLS-2$
    }

}
