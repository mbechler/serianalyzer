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


import java.lang.reflect.Modifier;

import org.apache.log4j.Logger;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;


/**
 * @author mbechler
 *
 */
public class SerianalyzerClassSerializationVisitor extends ClassVisitor implements SerianalyzerClassVisitorBase {

    private final Logger log;

    private String clName;
    private Serianalyzer analyzer;
    private boolean serializable;

    private boolean foundDefaultConstructor;


    /**
     * @param analyzer
     * @param clName
     * @param serializable
     * 
     */
    public SerianalyzerClassSerializationVisitor ( Serianalyzer analyzer, String clName, boolean serializable ) {
        super(Opcodes.ASM5);
        this.log = Logger.getLogger(serianalyzer.Serianalyzer.class.getName() + "." + clName); //$NON-NLS-1$
        this.log.debug("Found class " + clName); //$NON-NLS-1$
        this.analyzer = analyzer;
        this.clName = clName;
        this.serializable = serializable;
    }


    /**
     * @return the analyzer
     */
    @Override
    public Serianalyzer getAnalyzer () {
        return this.analyzer;
    }


    /**
     * @return the clName
     */
    @Override
    public String getClassName () {
        return this.clName.toString();
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.ClassVisitor#visitAttribute(org.objectweb.asm.Attribute)
     */
    @Override
    public void visitAttribute ( Attribute attr ) {
        this.log.debug("Found attribute " + attr); //$NON-NLS-1$
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.ClassVisitor#visitMethod(int, java.lang.String, java.lang.String, java.lang.String,
     *      java.lang.String[])
     */
    @Override
    public MethodVisitor visitMethod ( int access, String name, String desc, String signature, String[] exceptions ) {

        if ( isReachableMethod(name, desc, access) ) {
            if ( this.log.isTraceEnabled() ) {
                this.log.trace(String.format("Found %s::%s with signature %s", this.clName, name, desc)); //$NON-NLS-1$
            }

            this.foundDefaultConstructor = isDefaultConstructor(name, desc, access);
            MethodReference ref = new MethodReference(this.clName, false, name, ( access & Modifier.STATIC ) != 0, desc);
            if ( this.analyzer.getConfig().isWhitelisted(ref) ) {
                if ( this.log.isDebugEnabled() ) {
                    this.log.debug("Whitelisted " + ref); //$NON-NLS-1$
                }
                return super.visitMethod(access, name, desc, signature, exceptions);
            }
            ref.taintCallee();
            taintArguments(ref, name, desc, access);
            if ( this.serializable ) {
                this.getAnalyzer().getState().addInitial(ref);
            }

            return new SerianalyzerMethodVisitor(this, ref, ref.getTypeName());
        }
        else if ( this.serializable ) {
            MethodReference ref = new MethodReference(this.clName, false, name, ( access & Modifier.STATIC ) != 0, desc);
            if ( this.analyzer.getConfig().isWhitelisted(ref) ) {
                if ( this.log.isDebugEnabled() ) {
                    this.log.debug("Whitelisted " + ref); //$NON-NLS-1$
                }
                return super.visitMethod(access, name, desc, signature, exceptions);
            }
            if ( this.log.isDebugEnabled() ) {
                this.log.debug("Adding " + ref); //$NON-NLS-1$
            }
            ref.taintCallee();
            taintArguments(ref, name, desc, access);
            if ( this.analyzer.getConfig().isExtraCheckMethod(ref) ) {
                this.getAnalyzer().getState().addInitial(ref);
                return new SerianalyzerMethodVisitor(this, ref, ref.getTypeName());
            }

        }

        return super.visitMethod(access, name, desc, signature, exceptions);
    }


    /**
     * @param ref
     * @param name
     * @param signature
     * @param access
     */
    private static void taintArguments ( MethodReference ref, String name, String signature, int access ) {
        if ( "readObject".equals(name) && "(Ljava/io/ObjectInputStream;)V".equals(signature) ) { //$NON-NLS-1$ //$NON-NLS-2$
            ref.taintParameterReturns(0);
        }
        else if ( "readExternal".equals(name) && "(Ljava/io/ObjectInput;)V".equals(signature) ) { //$NON-NLS-1$//$NON-NLS-2$
            ref.taintParameterReturns(0);
        }
        else if ( "invoke".equals(name) && "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;".equals(signature) ) { //$NON-NLS-1$ //$NON-NLS-2$
            ref.taintParameter(0);
            ref.taintParameter(1);
            ref.taintParameter(2);
        }
    }


    /**
     * @return the foundDefaultConstructor
     */
    public boolean isFoundDefaultConstructor () {
        return this.foundDefaultConstructor;
    }


    /**
     * @param name
     * @param signature
     * @return
     */
    private boolean isReachableMethod ( String name, String signature, int access ) {
        return ( this.serializable && "toString".equals(name) )|| 
        		( this.serializable && "hashCode".equals(name) ) ||
        		( this.serializable && "equals".equals(name) ) ||
        		( this.serializable && "compareTo".equals(name) ) ||
        		( this.serializable && "readResolve".equals(name) ) ||
        		( this.serializable && "readObject".equals(name) && "(Ljava/io/ObjectInputStream;)V".equals(signature) ) || //$NON-NLS-1$ //$NON-NLS-2$
                ( this.serializable && "readExternal".equals(name) && "(Ljava/io/ObjectInput;)V".equals(signature) ) || //$NON-NLS-1$ //$NON-NLS-2$
                ( this.serializable && "readObjectNoData".equals(name) && "()V".equals(signature) ) || //$NON-NLS-1$ //$NON-NLS-2$
                ( this.serializable && "invoke".equals(name) //$NON-NLS-1$
                        && "(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;" //$NON-NLS-1$
                                .equals(signature) )
                || ( this.serializable && "$deserializeLambda$".equals(name) ) || isDefaultConstructor(name, signature, access) //$NON-NLS-1$
                || isStaticIntializer(name, access) || ( "finalize".equals(name) && "()V".equals(signature) ); //$NON-NLS-1$ //$NON-NLS-2$
    }


    /**
     * @param name
     * @param access
     * @return
     */
    private static boolean isStaticIntializer ( String name, int access ) {
        return ( ( access & Opcodes.ACC_STATIC ) != 0 && "<clinit>".equals(name) ); //$NON-NLS-1$
    }


    /**
     * @param name
     * @param signature
     * @param access
     * @return
     */
    private boolean isDefaultConstructor ( String name, String signature, int access ) {
        return !this.serializable && "<init>".equals(name) && "()V".equals(signature) && ( access & Opcodes.ACC_PUBLIC ) != 0; //$NON-NLS-1$ //$NON-NLS-2$
    }
}
