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


import org.apache.log4j.Logger;
import org.jboss.jandex.DotName;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;


/**
 * @author mbechler
 *
 */
public class SerianalyzerClassMethodVisitor extends ClassVisitor implements SerianalyzerClassVisitorBase {

    private final Logger log;

    private Serianalyzer analyzer;

    private MethodReference ref;

    private boolean found;

    private DotName actualType;


    /**
     * @param analyzer
     * @param ref
     * @param actualType
     * 
     */
    public SerianalyzerClassMethodVisitor ( Serianalyzer analyzer, MethodReference ref, DotName actualType ) {
        super(Opcodes.ASM5);
        this.actualType = actualType;
        this.log = Logger.getLogger(Serianalyzer.class.getName() + "." + ref.getTypeNameString() + "." + ref.getMethod()); //$NON-NLS-1$ //$NON-NLS-2$
        this.analyzer = analyzer;
        this.ref = ref;
        if ( this.log.isTraceEnabled() ) {
            this.log.trace("Trying to find " + ref); //$NON-NLS-1$
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see serianalyzer.SerianalyzerClassVisitorBase#getClassName()
     */
    @Override
    public String getClassName () {
        return this.actualType.toString();
    }


    /**
     * @return the analyzer
     */
    @Override
    public Serianalyzer getAnalyzer () {
        return this.analyzer;
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.ClassVisitor#visitMethod(int, java.lang.String, java.lang.String, java.lang.String,
     *      java.lang.String[])
     */
    @Override
    public MethodVisitor visitMethod ( int access, String name, String desc, String signature, String[] exceptions ) {
        if ( this.ref.getMethod().equals(name) && this.ref.getSignature().equals(desc) ) {
            if ( this.log.isTraceEnabled() ) {
                this.log.trace(String.format("Found %s::%s with signature %s", this.ref.getTypeNameString(), name, desc)); //$NON-NLS-1$
            }
            if ( ( access & Opcodes.ACC_ABSTRACT ) != 0 ) {
                return super.visitMethod(access, name, desc, signature, exceptions);
            }
            this.found = true;
            if ( ( access & Opcodes.ACC_NATIVE ) != 0 ) {
                this.analyzer.getState().nativeCall(this.ref);
                return super.visitMethod(access, name, desc, signature, exceptions);
            }

            return new SerianalyzerMethodVisitor(this, this.ref, this.actualType);
        }

        if ( this.log.isTraceEnabled() ) {
            this.log.trace(String.format("Mismatch %s %s %s vs. %s", name, desc, signature, this.ref)); //$NON-NLS-1$
        }

        return super.visitMethod(access, name, desc, signature, exceptions);
    }


    /**
     * @return the found
     */
    public boolean isFound () {
        return this.found;
    }
}
