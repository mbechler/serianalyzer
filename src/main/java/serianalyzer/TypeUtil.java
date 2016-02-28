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
 * Created: 14.11.2015 by mbechler
 */
package serianalyzer;


import java.io.Serializable;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

import org.apache.log4j.Logger;
import org.jboss.jandex.ArrayType;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.ClassInfo.NestingType;
import org.jboss.jandex.ClassType;
import org.jboss.jandex.DotName;
import org.jboss.jandex.Index;
import org.jboss.jandex.MethodInfo;
import org.jboss.jandex.ParameterizedType;
import org.jboss.jandex.PrimitiveType;
import org.jboss.jandex.Type.Kind;
import org.jboss.jandex.TypeVariable;
import org.jboss.jandex.UnresolvedTypeVariable;
import org.jboss.jandex.VoidType;
import org.objectweb.asm.Type;


/**
 * @author mbechler
 *
 */
public final class TypeUtil {

    private static final Logger log = Logger.getLogger(TypeUtil.class);


    /**
     * 
     */
    private TypeUtil () {}


    /**
     * @param p
     * @throws SerianalyzerException
     */
    static String toString ( org.jboss.jandex.Type p ) throws SerianalyzerException {
        if ( p instanceof VoidType ) {
            return "V"; //$NON-NLS-1$
        }
        else if ( p instanceof PrimitiveType ) {
            switch ( ( (PrimitiveType) p ).primitive() ) {
            case BOOLEAN:
                return "Z"; //$NON-NLS-1$
            case BYTE:
                return "B"; //$NON-NLS-1$
            case CHAR:
                return "C"; //$NON-NLS-1$
            case DOUBLE:
                return "D"; //$NON-NLS-1$
            case FLOAT:
                return "F"; //$NON-NLS-1$
            case INT:
                return "I"; //$NON-NLS-1$
            case LONG:
                return "J"; //$NON-NLS-1$
            case SHORT:
                return "S"; //$NON-NLS-1$
            default:
                throw new SerianalyzerException();
            }
        }
        else if ( p instanceof ArrayType ) {
            return "[" + toString( ( (ArrayType) p ).component()); //$NON-NLS-1$
        }
        else if ( p instanceof ClassType ) {
            return "L" + p.name().toString().replace('.', '/') + ";"; //$NON-NLS-1$ //$NON-NLS-2$
        }
        else if ( p instanceof ParameterizedType ) {
            return "L" + ( (ParameterizedType) p ).name().toString().replace('.', '/') + ";"; //$NON-NLS-1$ //$NON-NLS-2$
        }
        else if ( p instanceof TypeVariable ) {
            return toString( ( (TypeVariable) p ).bounds().get(0));
        }
        else if ( p instanceof UnresolvedTypeVariable ) {
            return "Ljava/lang/Object;"; //$NON-NLS-1$
        }

        log.warn("Unhandled type " + p.getClass()); //$NON-NLS-1$

        return ""; //$NON-NLS-1$
    }


    /**
     * @param i
     * @return
     * @throws SerianalyzerException
     */
    static String makeSignature ( MethodInfo i, boolean fix ) throws SerianalyzerException {

        StringBuilder sb = new StringBuilder();
        sb.append('(');
        ClassInfo declaringImpl = i.declaringClass();
        if ( fix && "<init>".equals(i.name()) && declaringImpl.nestingType() == NestingType.INNER ) { //$NON-NLS-1$
            // there seems to be some sort of bug, missing the the outer instance parameter in the constructor
            if ( !Modifier.isStatic(declaringImpl.flags()) ) {
                org.jboss.jandex.Type enclosingClass = org.jboss.jandex.Type.create(declaringImpl.enclosingClass(), Kind.CLASS);
                org.jboss.jandex.Type firstArg = i.parameters().size() > 0 ? i.parameters().get(0) : null;
                if ( firstArg instanceof TypeVariable ) {
                    firstArg = firstArg.asTypeVariable().bounds().get(0);
                }
                if ( firstArg == null || !firstArg.equals(enclosingClass) ) {
                    sb.append(toString(enclosingClass));
                }
            }
        }

        for ( org.jboss.jandex.Type p : i.parameters() ) {
            sb.append(toString(p));
        }
        sb.append(')');
        sb.append(toString(i.returnType()));
        return sb.toString();
    }


    /**
     * @param methodReference
     * @param impl
     * @return
     */
    static boolean implementsMethod ( MethodReference methodReference, ClassInfo impl ) {
        for ( MethodInfo i : impl.methods() ) {
            if ( methodReference.getMethod().equals(i.name()) ) {
                String sig2;
                try {
                    sig2 = makeSignature(i, false);
                    if ( sig2.equals(methodReference.getSignature()) ) {
                        return true;
                    }

                    log.trace("Signature mismatch " + methodReference.getSignature() + " vs " + sig2); //$NON-NLS-1$ //$NON-NLS-2$

                    if ( "<init>".equals(methodReference.getMethod()) ) { //$NON-NLS-1$
                        sig2 = makeSignature(i, true);
                        if ( sig2.equals(methodReference.getSignature()) ) {
                            return true;
                        }
                    }
                }
                catch ( SerianalyzerException e1 ) {
                    log.warn("Failed to generate signature", e1); //$NON-NLS-1$
                }

                return true;
            }
        }
        return false;
    }


    /**
     * @param methodReference
     * @param fixedType
     * @param serializableOnly
     * @param doBench
     * @param i
     * @return
     */
    static Collection<ClassInfo> findImplementors ( MethodReference methodReference, boolean ignoreNonFound, boolean fixedType,
            boolean serializableOnly, Benchmark bench, Index i ) {
        Collection<ClassInfo> impls;
        DotName tn = methodReference.getTypeName();
        if ( fixedType ) {
            ClassInfo root = i.getClassByName(tn);
            if ( root == null ) {
                if ( ignoreNonFound ) {
                    log.debug("Class not found " + methodReference.getTypeNameString()); //$NON-NLS-1$
                }
                else {
                    log.error("Class not found " + methodReference.getTypeNameString()); //$NON-NLS-1$
                }
                return Collections.EMPTY_LIST;
            }

            ClassInfo cur = root;

            while ( cur != null ) {
                if ( TypeUtil.implementsMethod(methodReference, cur) ) {
                    return Arrays.asList(cur);
                }
                cur = i.getClassByName(cur.superName());
            }

            cur = root;
            while ( cur != null ) {
                // seems we cannot really determine whether there is a default method
                // probably jandex is missing a flag for this
                log.debug("Looking for default impl in interfaces for " + root); //$NON-NLS-1$
                List<ClassInfo> checkInterfaces = TypeUtil.checkInterfaces(i, methodReference, cur);
                if ( checkInterfaces != null ) {
                    return checkInterfaces;
                }

                cur = i.getClassByName(cur.superName());
            }

            log.error("No method implementor found for " + methodReference); //$NON-NLS-1$
            return Collections.EMPTY_LIST;
        }
        else if ( methodReference.isInterface() ) {
            Collection<ClassInfo> tmp = i.getAllKnownImplementors(tn);
            if ( serializableOnly ) {
                impls = new ArrayList<>();
                for ( ClassInfo ci : tmp ) {
                    if ( TypeUtil.implementsMethod(methodReference, ci) && TypeUtil.isSerializable(i, ci) ) {
                        impls.add(ci);
                    }
                }
                return impls;
            }

            impls = new ArrayList<>();
            for ( ClassInfo ci : tmp ) {
                if ( TypeUtil.implementsMethod(methodReference, ci) ) {
                    impls.add(ci);
                }
            }

            if ( bench != null ) {
                bench.unboundedInterfaceCalls();
            }
            return impls;
        }
        else {
            ClassInfo classByName = i.getClassByName(tn);
            if ( classByName == null ) {
                if ( !ignoreNonFound ) {
                    log.error("Class not found " + tn); //$NON-NLS-1$
                }
                else {
                    log.debug("Class not found " + tn); //$NON-NLS-1$
                }
                return Collections.EMPTY_LIST;
            }

            impls = new HashSet<>();
            for ( ClassInfo ci : i.getAllKnownSubclasses(tn) ) {
                if ( TypeUtil.implementsMethod(methodReference, ci) ) {
                    impls.add(ci);
                }
            }

            if ( TypeUtil.implementsMethod(methodReference, classByName) ) {
                impls.add(classByName);
            }
            return impls;
        }
    }


    /**
     * @param e
     */
    static void checkReferenceTyping ( Index i, boolean ignoreNonFound, MethodReference ref ) {
        if ( !ref.isStatic() ) {
            Type t = ref.getTargetType();
            Type sigType = Type.getObjectType(ref.getTypeNameString().replace('.', '/'));
            if ( t == null ) {
                t = sigType;
            }
            else {
                try {
                    TypeUtil.getMoreConcreteType(i, ignoreNonFound, t, sigType);
                }
                catch ( SerianalyzerException e ) {
                    log.warn("Failed to determine target type", e); //$NON-NLS-1$
                    log.warn("Failing type " + t); //$NON-NLS-1$
                    log.warn("Signature type " + sigType); //$NON-NLS-1$
                    log.warn("For " + ref); //$NON-NLS-1$
                    System.exit(-1);
                }
            }
        }

        Type[] argumentTypes = Type.getArgumentTypes(ref.getSignature());

        if ( ref.getArgumentTypes() != null && ref.getArgumentTypes().size() == argumentTypes.length ) {
            for ( int k = 0; k < argumentTypes.length; k++ ) {
                try {
                    TypeUtil.getMoreConcreteType(i, ignoreNonFound, ref.getArgumentTypes().get(k), argumentTypes[ k ]);
                }
                catch ( SerianalyzerException e ) {
                    log.warn("Failed to determine argument type", e); //$NON-NLS-1$
                    log.warn("Failing type " + ref.getArgumentTypes().get(k)); //$NON-NLS-1$
                    log.warn("Signature type " + argumentTypes[ k ]); //$NON-NLS-1$
                    log.warn("For " + ref); //$NON-NLS-1$
                    System.exit(-1);
                }
            }
        }

    }


    /**
     * 
     * @param i
     * @param ignoreNotFound
     * @param a
     * @param b
     *            acts as fallback
     * @return the more concrete type
     * @throws SerianalyzerException
     */
    public static Type getMoreConcreteType ( Index i, boolean ignoreNotFound, Type a, Type b ) throws SerianalyzerException {
        if ( a == Type.VOID_TYPE ) {
            return b;
        }
        else if ( b == Type.VOID_TYPE ) {
            return a;
        }

        if ( ! ( a.getSort() == Type.OBJECT || a.getSort() == Type.ARRAY ) && ! ( b.getSort() == Type.OBJECT || b.getSort() == Type.ARRAY ) ) {
            return b;
        }
        else if ( ! ( a.getSort() == Type.OBJECT || a.getSort() == Type.ARRAY ) ^ ! ( b.getSort() == Type.OBJECT || b.getSort() == Type.ARRAY ) ) {
            throw new SerianalyzerException("Incompatible object/non-object types " + a + " " + a.getSort() //$NON-NLS-1$//$NON-NLS-2$
                    + " and " + b + " " + b.getSort()); //$NON-NLS-1$ //$NON-NLS-2$
        }

        if ( "java.lang.Object".equals(a.getClassName()) ) { //$NON-NLS-1$
            return b;
        }
        else if ( "java.lang.Object".equals(b.getClassName()) ) { //$NON-NLS-1$
            return a;
        }

        if ( "java.io.Serializable".equals(a.getClassName()) ) { //$NON-NLS-1$
            return b;
        }
        else if ( "java.io.Serializable".equals(b.getClassName()) ) { //$NON-NLS-1$
            return a;
        }

        if ( a.toString().charAt(0) == '[' && b.toString().charAt(0) == '[' ) {
            return Type.getType(
                "[" + getMoreConcreteType(i, ignoreNotFound, Type.getType(a.toString().substring(1)), Type.getType(b.toString().substring(1)))); //$NON-NLS-1$
        }
        else if ( a.toString().charAt(0) == '[' ^ b.toString().charAt(0) == '[' ) {
            throw new SerianalyzerException("Incompatible array/non-array types " + a + " and " + b); //$NON-NLS-1$ //$NON-NLS-2$
        }

        DotName aName = DotName.createSimple(a.getClassName());
        ClassInfo aInfo = i.getClassByName(aName);
        DotName bName = DotName.createSimple(b.getClassName());
        ClassInfo bInfo = i.getClassByName(bName);

        if ( aInfo == null ) {
            if ( ignoreNotFound ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Type not found " + a.getClassName()); //$NON-NLS-1$
                }
                return b;
            }
            throw new SerianalyzerException("A type not found " + a.getClassName()); //$NON-NLS-1$
        }
        if ( bInfo == null ) {
            if ( ignoreNotFound ) {
                if ( log.isDebugEnabled() ) {
                    log.debug("Type not found " + b.getClassName()); //$NON-NLS-1$
                }
                return b;
            }
            throw new SerianalyzerException("B type not found " + b.getClassName()); //$NON-NLS-1$
        }

        if ( aInfo.equals(bInfo) ) {
            return a;
        }

        if ( Modifier.isInterface(aInfo.flags()) && Modifier.isInterface(bInfo.flags()) ) {
            if ( extendsInterface(i, aInfo, bName) ) {
                return a;
            }
            else if ( extendsInterface(i, bInfo, aName) ) {
                return b;
            }
        }
        else if ( Modifier.isInterface(aInfo.flags()) ) {
            if ( extendsInterface(i, bInfo, aInfo.name()) ) {
                return b;
            }
        }
        else if ( Modifier.isInterface(bInfo.flags()) ) {
            if ( extendsInterface(i, aInfo, bInfo.name()) ) {
                return a;
            }
        }

        if ( extendsClass(i, aInfo, bInfo) ) {
            return a;
        }
        else if ( extendsClass(i, bInfo, aInfo) ) {
            return b;
        }
        else {
            throw new SerianalyzerException("Incompatible non-assignable types " + a + " and " + b); //$NON-NLS-1$ //$NON-NLS-2$
        }
    }


    /**
     * @param bInfo
     * @param aInfo
     * @return
     * @throws SerianalyzerException
     */
    private static boolean extendsClass ( Index i, ClassInfo extendor, ClassInfo base ) throws SerianalyzerException {
        if ( extendor.equals(base) ) {
            return true;
        }
        DotName superName = extendor.superName();
        if ( superName != null ) {
            ClassInfo superByName = i.getClassByName(superName);
            if ( superByName == null ) {
                throw new SerianalyzerException("Failed to find super class " + superName); //$NON-NLS-1$
            }
            return extendsClass(i, superByName, base);
        }
        return false;
    }


    /**
     * @param aInfo
     * @param bName
     * @return
     */
    private static boolean extendsInterface ( Index i, ClassInfo info, DotName ifName ) {

        if ( info == null || info.name() == null ) {
            log.error("Info is NULL " + info); //$NON-NLS-1$
            return false;
        }

        if ( info.name().equals(ifName) ) {
            return true;
        }

        for ( DotName checkName : info.interfaceNames() ) {
            ClassInfo classByName = i.getClassByName(checkName);
            if ( classByName == null ) {
                log.error("Failed to find interface " + checkName); //$NON-NLS-1$
                continue;
            }
            if ( extendsInterface(i, classByName, ifName) ) {
                return true;
            }
        }

        DotName superName = info.superName();
        if ( superName != null ) {
            ClassInfo classByName = i.getClassByName(superName);
            if ( classByName == null ) {
                log.warn("Failed to find interface " + superName); //$NON-NLS-1$
                return false;
            }
            return extendsInterface(i, i.getClassByName(superName), ifName);
        }

        return false;
    }


    /**
     * @param impl
     * @return
     */
    static boolean isSerializable ( Index i, ClassInfo impl ) {

        if ( impl == null ) {
            return false;
        }

        for ( DotName ifName : impl.interfaceNames() ) {

            if ( DotName.createSimple(Serializable.class.getName()).equals(ifName) ) {
                return true;
            }

            ClassInfo classByName = i.getClassByName(ifName);
            if ( classByName == null ) {
                log.debug("Failed to find implemented interface " + ifName); //$NON-NLS-1$
                return false;
            }
            if ( isSerializable(i, classByName) ) {
                return true;
            }
        }

        if ( impl.superName() == null ) {
            return false;
        }
        ClassInfo classByName = i.getClassByName(impl.superName());
        if ( classByName == null ) {
            log.debug("Failed to find superclass " + impl.superName()); //$NON-NLS-1$
            return false;
        }
        return isSerializable(i, classByName);
    }


    /**
     * @param methodReference
     * @param cur
     * @return
     */
    static List<ClassInfo> checkInterfaces ( Index i, MethodReference methodReference, ClassInfo cur ) {
        for ( DotName ifName : cur.interfaceNames() ) {
            ClassInfo ifImpl = i.getClassByName(ifName);
            if ( ifImpl == null ) {
                log.warn("Failed to find interface " + ifName); //$NON-NLS-1$
                continue;
            }
            if ( implementsMethod(methodReference, ifImpl) ) {
                return Arrays.asList(ifImpl);
            }

            List<ClassInfo> checkInterfaces = checkInterfaces(i, methodReference, ifImpl);
            if ( checkInterfaces != null ) {
                return checkInterfaces;
            }
        }

        return null;
    }
}
