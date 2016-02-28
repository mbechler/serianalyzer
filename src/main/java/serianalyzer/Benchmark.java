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
 * Created: 14.11.2015 by mbechler
 */
package serianalyzer;


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
    private int methodLimitReached;


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
    public void reachedMethodLimit () {
        this.methodLimitReached++;
    }


    /**
     * 
     */
    public void dump () {
        log.info("Total calls " + ( this.taintedCall + this.untaintedCall )); //$NON-NLS-1$
        log.info("Tainted calls " + this.taintedCall); //$NON-NLS-1$
        log.info("Calls tainted by unknown arguments " + this.taintedByMissingArgs); //$NON-NLS-1$
        log.info("Calls tainted by limit reached " + this.methodLimitReached); //$NON-NLS-1$
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
