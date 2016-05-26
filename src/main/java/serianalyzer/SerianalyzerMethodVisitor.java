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


import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.jboss.jandex.DotName;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import serianalyzer.types.BaseType;
import serianalyzer.types.BasicVariable;
import serianalyzer.types.FieldReference;
import serianalyzer.types.MultiAlternatives;
import serianalyzer.types.ObjectReferenceConstant;
import serianalyzer.types.SimpleType;


/**
 * @author mbechler
 *
 */
public class SerianalyzerMethodVisitor extends MethodVisitor {

    private SerianalyzerClassVisitorBase parent;

    private boolean foundCall = false;

    private MethodReference ref;

    private List<Label> foundLabels = new ArrayList<>();
    private Set<Label> backwardJumpsToLabels = new HashSet<>();
    private Set<Type> returnTypes = new HashSet<>();
    private Set<MethodReference> foundRefs = new HashSet<>();
    private boolean foundJump;

    private Logger log;

    private JVMStackState stack = new JVMStackState();


    /**
     * @param api
     */
    @SuppressWarnings ( "javadoc" )
    public SerianalyzerMethodVisitor ( SerianalyzerClassVisitorBase parent, MethodReference ref, DotName actualClass ) {
        super(Opcodes.ASM5);

        this.log = Verbose.getPerMethodLogger(ref);
        this.parent = parent;
        this.ref = ref;

        if ( this.log.isDebugEnabled() ) {
            this.log.debug("Method signature " + ref); //$NON-NLS-1$
            this.log.debug("Known callers are " + parent.getAnalyzer().getState().getMethodCallers().get(ref.comparable())); //$NON-NLS-1$
        }

        int i = 0;
        if ( !ref.isStatic() ) {
            Type t = ref.getTargetType();
            if ( t == null ) {
                t = Type.getObjectType(ref.getTypeNameString().replace('.', '/'));
            }
            if ( this.log.isDebugEnabled() ) {
                this.log.debug("Adding this with type " + t); //$NON-NLS-1$
            }
            this.stack.getVariable(i++).add(new FieldReference(actualClass, "this", t, ref.isCalleeTainted(), true)); //$NON-NLS-1$
        }
        else if ( this.log.isDebugEnabled() ) {
            this.log.debug("Static call"); //$NON-NLS-1$
        }

        Type[] argumentTypes = Type.getArgumentTypes(ref.getSignature());
        if ( ref.getArgumentTypes() != null && ref.getArgumentTypes().length == argumentTypes.length ) {
            argumentTypes = ref.getArgumentTypes();
        }
        else {
            this.log.debug("Do not have actual argument types " + ref.getArgumentTypes()); //$NON-NLS-1$
        }

        for ( int j = 0; j < argumentTypes.length; j++ ) {
            BasicVariable o = new BasicVariable(
                argumentTypes[ j ],
                "param" + j + ":" + argumentTypes[ j ], //$NON-NLS-1$ //$NON-NLS-2$
                ref.isParameterTainted(j),
                ref.isTaintParameterReturn(j));

            if ( argumentTypes[ j ] == Type.LONG_TYPE || argumentTypes[ j ] == Type.DOUBLE_TYPE ) {
                i++;
            }

            if ( this.log.isDebugEnabled() ) {
                this.log.debug("Adding parameter " + i + ": " + o); //$NON-NLS-1$ //$NON-NLS-2$
            }

            this.stack.getVariable(i++).add(o);
        }

    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitLabel(org.objectweb.asm.Label)
     */
    @Override
    public void visitLabel ( Label label ) {
        this.foundLabels.add(label);
        if ( this.foundJump ) {
            if ( this.log.isTraceEnabled() ) {
                this.log.trace("Clearing stack on label " + label); //$NON-NLS-1$
            }
            this.stack.clear();
        }
        super.visitLabel(label);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitJumpInsn(int, org.objectweb.asm.Label)
     */
    @Override
    public void visitJumpInsn ( int opcode, Label label ) {
        this.foundJump = true;
        boolean tainted = JVMImpl.handleJVMJump(opcode, label, this.stack);

        if ( this.foundLabels.contains(label) ) {
            this.backwardJumpsToLabels.add(label);
            if ( this.log.isTraceEnabled() ) {
                this.log.trace( ( tainted ? "Tainted " : "" ) + "backward jump to " + label.toString()); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            }
        }
        else {
            if ( this.log.isTraceEnabled() ) {
                this.log.trace( ( tainted ? "Tainted " : "" ) + "forward jump to " + label.toString()); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            }
        }

        super.visitJumpInsn(opcode, label);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitFieldInsn(int, java.lang.String, java.lang.String, java.lang.String)
     */
    @Override
    public void visitFieldInsn ( int opcode, String owner, String name, String desc ) {
        JVMStackState s = this.stack;
        if ( opcode == Opcodes.PUTSTATIC ) {
            Object v = s.pop();

            if ( ! ( v instanceof BaseType ) || ( (BaseType) v ).isTainted() ) {

                // generated static cached, let's assume they are safe
                if ( name.indexOf('$') < 0 && this.ref.getMethod().indexOf('$') < 0 ) {
                    this.parent.getAnalyzer().putstatic(this.ref);
                }
            }
        }
        else {
            JVMImpl.handleFieldInsn(opcode, owner, name, desc, s);
        }

        if ( ( opcode == Opcodes.GETSTATIC || opcode == Opcodes.GETFIELD ) && name.indexOf('$') < 0 ) {
            this.parent.getAnalyzer().instantiable(this.ref, Type.getType(desc));
        }

        super.visitFieldInsn(opcode, owner, name, desc);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitIntInsn(int, int)
     */
    @Override
    public void visitIntInsn ( int opcode, int operand ) {
        JVMImpl.handleJVMIntInsn(opcode, operand, this.stack);
        super.visitIntInsn(opcode, operand);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitVarInsn(int, int)
     */
    @Override
    public void visitVarInsn ( int opcode, int var ) {
        JVMImpl.handleVarInsn(opcode, var, this.stack);
        super.visitVarInsn(opcode, var);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitInsn(int)
     */
    @Override
    public void visitInsn ( int opcode ) {

        switch ( opcode ) {
        case Opcodes.ARETURN:
            Object ret = this.stack.pop();
            Type sigType = Type.getReturnType(this.ref.getSignature());
            Type retType = null;
            Set<Type> altTypes = null;
            if ( ret != null ) {
                if ( ret instanceof SimpleType ) {
                    retType = ( (SimpleType) ret ).getType();
                    altTypes = ( (SimpleType) ret ).getAlternativeTypes();
                }
                else if ( ret instanceof MultiAlternatives ) {
                    retType = ( (MultiAlternatives) ret ).getCommonType();
                }
            }

            if ( retType != null ) {
                this.returnTypes.add(retType);
                if ( altTypes != null ) {
                    this.returnTypes.addAll(altTypes);
                }
            }
            else {
                this.returnTypes.add(sigType);
            }
            this.stack.clear();
            break;

        case Opcodes.IRETURN:
        case Opcodes.LRETURN:
        case Opcodes.FRETURN:
        case Opcodes.DRETURN:
        case Opcodes.RETURN:
            if ( this.log.isTraceEnabled() ) {
                this.log.trace("Found return " + this.stack.pop()); //$NON-NLS-1$
            }
            this.stack.clear();
            break;

        case Opcodes.ATHROW:
            Object thrw = this.stack.pop();
            this.log.trace("Found throw " + thrw); //$NON-NLS-1$
            this.stack.clear();
            break;

        default:
            JVMImpl.handleJVMInsn(opcode, this.stack);
        }

        super.visitInsn(opcode);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitLdcInsn(java.lang.Object)
     */
    @Override
    public void visitLdcInsn ( Object cst ) {
        JVMImpl.handleLdcInsn(cst, this.stack);
        super.visitLdcInsn(cst);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitInvokeDynamicInsn(java.lang.String, java.lang.String,
     *      org.objectweb.asm.Handle, java.lang.Object[])
     */
    @Override
    public void visitInvokeDynamicInsn ( String name, String desc, Handle bsm, Object... bsmArgs ) {
        if ( bsm.getTag() == Opcodes.H_INVOKESTATIC
                && ( bsm.getName().equals("metafactory") || //$NON-NLS-1$
                        bsm.getName().equals("altMetafactory") ) //$NON-NLS-1$
                && bsm.getOwner().equals("java/lang/invoke/LambdaMetafactory") && bsmArgs.length >= 2 ) { //$NON-NLS-1$
            Handle h = (Handle) bsmArgs[ 1 ];
            Type[] handleArgs = Type.getArgumentTypes(h.getDesc());
            Type[] formalArgs = Type.getArgumentTypes(desc);

            List<BaseType> args = this.stack.pop(formalArgs.length);
            boolean tainted = checkTainted(formalArgs, args);

            String className = Type.getObjectType(h.getOwner()).getClassName();
            boolean isStatic = h.getTag() == Opcodes.H_INVOKESTATIC;
            MethodReference r = new MethodReference(className, false, h.getName(), isStatic, h.getDesc());

            this.foundRefs.add(r);
            if ( tainted ) {
                if ( !Arrays.equals(handleArgs, formalArgs) ) {
                    if ( this.log.isDebugEnabled() ) {
                        this.log.debug("Mismatch between formal args and handle args in " + this.ref + " " + name); //$NON-NLS-1$ //$NON-NLS-2$
                        this.log.debug("Handle arguments are " + Arrays.toString(handleArgs)); //$NON-NLS-1$
                        this.log.debug("Formal arguments are " + Arrays.toString(formalArgs)); //$NON-NLS-1$
                        this.log.debug("BSM arguments are " + Arrays.toString(bsmArgs)); //$NON-NLS-1$
                    }
                    this.parent.getAnalyzer().getState().getBench().unhandledLambda();
                    r.setArgumentTypes(setupTainting(r, Opcodes.INVOKEDYNAMIC, Collections.EMPTY_LIST, null, r, handleArgs));
                }
                else {
                    r.setArgumentTypes(setupTainting(r, Opcodes.INVOKEDYNAMIC, args, null, r, handleArgs));
                }
                this.parent.getAnalyzer().getState().getBench().taintedCall();

                if ( this.log.isDebugEnabled() ) {
                    this.log.debug(String.format(
                        "In %s need to check lambda %s %s::%s %s (%s): %s", //$NON-NLS-1$
                        this.ref,
                        bsm.getTag(),
                        bsm.getOwner(),
                        bsm.getName(),
                        desc,
                        bsm.getDesc(),
                        Arrays.toString(bsmArgs)));
                    this.log.debug(String.format("In %s need to check lambda %s::%s (%s)", this.ref, h.getOwner(), h.getName(), h.getDesc())); //$NON-NLS-1$
                    this.log.debug("Arguments " + args); //$NON-NLS-1$
                }

                boolean unsafeCall = this.parent.getAnalyzer().checkMethodCall(r, Collections.singleton(this.ref), true, false);
                if ( !unsafeCall ) {
                    this.log.debug("Call is safe"); //$NON-NLS-1$
                }
                this.foundCall = true;
            }
            else {
                this.parent.getAnalyzer().getState().traceCalls(r, Collections.singleton(this.ref));
                this.parent.getAnalyzer().getState().getBench().untaintedCall();
            }

            Type returnType = Type.getReturnType(desc);
            if ( returnType != Type.VOID_TYPE ) {
                this.stack.push(new BasicVariable(returnType, "return " + r, tainted)); //$NON-NLS-1$
            }
        }
        else {
            this.log.warn("Unsupported dynamic call in " + this.ref); //$NON-NLS-1$
            this.log.warn(String.format(
                "In %s need to check lambda %s %s::%s %s (%s): %s", //$NON-NLS-1$
                this.ref,
                bsm.getTag(),
                bsm.getOwner(),
                bsm.getName(),
                desc,
                bsm.getDesc(),
                Arrays.toString(bsmArgs)));
        }

        super.visitInvokeDynamicInsn(name, desc, bsm, bsmArgs);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitMethodInsn(int, java.lang.String, java.lang.String, java.lang.String,
     *      boolean)
     */
    @Override
    public void visitMethodInsn ( int opcode, String owner, String name, String desc, boolean itf ) {

        String clName = Type.getObjectType(owner).getClassName();

        if ( opcode == Opcodes.INVOKESTATIC && "class$".equals(name) && clName.equals(this.ref.getTypeNameString()) ) { //$NON-NLS-1$
            // this is compiler generated for static .class references
            super.visitMethodInsn(opcode, owner, clName, desc, itf);
            return;
        }

        Type[] formalArgumentTypes = Type.getArgumentTypes(desc);
        List<BaseType> args = this.stack.pop(formalArgumentTypes.length);
        boolean tainted = checkTainted(formalArgumentTypes, args) || opcode == Opcodes.INVOKESTATIC;
        boolean fixedType = opcode == Opcodes.INVOKESTATIC || ( opcode == Opcodes.INVOKESPECIAL );
        boolean deserializedTarget = false;
        Object tgt = null;

        Type tgtType = null;
        Set<Type> tgtAltTypes = null;
        if ( opcode != Opcodes.INVOKESTATIC ) {
            tgt = this.stack.pop();
            if ( ! ( tgt instanceof BaseType ) ) {
                this.log.trace("Target not found"); //$NON-NLS-1$
                tainted = true;
            }
            else {
                tainted |= ( (BaseType) tgt ).isTainted();
                if ( tgt instanceof ObjectReferenceConstant ) {
                    if ( opcode != Opcodes.INVOKESPECIAL ) {
                        clName = ( (ObjectReferenceConstant) tgt ).getClassName();
                    }
                    fixedType = true;
                }
                if ( tgt instanceof SimpleType ) {
                    tgtType = ( (SimpleType) tgt ).getType();
                    tgtAltTypes = ( (SimpleType) tgt ).getAlternativeTypes();
                }
            }
        }

        MethodReference r = new MethodReference(clName, itf, name, opcode == Opcodes.INVOKESTATIC, desc);
        r.setArgumentTypes(setupTainting(r, opcode, args, tgt, r, formalArgumentTypes));
        String realOwner = owner;
        int realOpcode = opcode;

        // optimize away doPrivileged calls, were more interested in the call target
        if ( "java.security.AccessController".equals(clName) && "doPrivileged".equals(name) ) { //$NON-NLS-1$ //$NON-NLS-2$
            if ( this.parent.getAnalyzer().getConfig().isDumpPrivileged() ) {
                this.parent.getAnalyzer().getState().reportCall(r);
                this.parent.getAnalyzer().getState().traceCalls(r, Collections.singleton(this.ref));
            }
            if ( !args.isEmpty() && args.get(0) instanceof ObjectReferenceConstant ) {
                ObjectReferenceConstant privAction = (ObjectReferenceConstant) args.get(0);
                String privActionClass = privAction.getClassName();
                if ( this.log.isDebugEnabled() ) {
                    this.log.debug("Replacing doPrivileged in " + this.ref + " with " + privActionClass); //$NON-NLS-1$ //$NON-NLS-2$
                }
                r = new MethodReference(privActionClass, false, "run", false, "()Ljava/lang/Object;"); //$NON-NLS-1$//$NON-NLS-2$
                tgt = privAction;
                realOwner = privAction.getClassName();
                if ( privAction.isTainted() ) {
                    tainted = true;
                    r.taintCallee();
                }
            }
            else {
                if ( this.log.isDebugEnabled() ) {
                    this.log.debug("Missing target information for doPrivileged in " + this.ref); //$NON-NLS-1$
                }
                r = new MethodReference(PrivilegedAction.class.getName(), true, "run", false, "()Ljava/lang/Object;"); //$NON-NLS-1$//$NON-NLS-2$
                r.taintCallee();
                tainted = true;
                fixedType = false;
            }
            deserializedTarget = false;
            realOpcode = Opcodes.INVOKEDYNAMIC;
        }

        Type sigTgtType = Type.getObjectType(realOwner);
        if ( tgtType != null && ( tgtAltTypes == null || tgtAltTypes.isEmpty() ) ) {
            try {
                Type moreConcreteType = this.parent.getAnalyzer().getMoreConcreteType(tgtType, sigTgtType);
                if ( this.log.isDebugEnabled() && !moreConcreteType.equals(sigTgtType) ) {
                    this.log.debug("Improving target type to " + moreConcreteType + " for " + r + " in " + this.ref); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                }
                r.setTargetType(moreConcreteType);
            }
            catch ( SerianalyzerException e ) {
                this.log.error("Failed to determine target type", e); //$NON-NLS-1$
                this.log.warn("Failing target " + tgt); //$NON-NLS-1$
                this.log.warn("Failing type " + tgtType); //$NON-NLS-1$
                this.log.warn("Signature type " + sigTgtType); //$NON-NLS-1$
                this.log.warn("In " + this.ref); //$NON-NLS-1$
                this.log.warn("Calling " + r); //$NON-NLS-1$
            }
        }

        this.foundRefs.add(r);
        if ( tainted ) {
            if ( this.log.isDebugEnabled() ) {
                this.log.debug(String.format(
                    "Tainted invoke%s method %s::%s (%s,%d,%s)", //$NON-NLS-1$
                    realOpcode == Opcodes.INVOKESTATIC ? " static" : "", //$NON-NLS-1$ //$NON-NLS-2$
                    clName,
                    name,
                    desc,
                    opcode,
                    itf));
                this.log.debug("  Arguments " + args); //$NON-NLS-1$
                if ( realOpcode != Opcodes.INVOKESTATIC ) {
                    this.log.debug("  Target " + tgt); //$NON-NLS-1$
                }
            }
            if ( tgt instanceof BaseType ) {
                ( (BaseType) tgt ).taint();
            }
            this.parent.getAnalyzer().getState().getBench().taintedCall();

            this.parent.getAnalyzer().checkMethodCall(r, Collections.singleton(this.ref), fixedType, deserializedTarget);
            this.foundCall = true;
        }
        else {
            if ( this.log.isDebugEnabled() ) {
                this.log.debug(String.format(
                    "Untainted invoke%s method %s::%s (%s,%d,%s)", //$NON-NLS-1$
                    opcode == Opcodes.INVOKESTATIC ? " static" : "", //$NON-NLS-1$ //$NON-NLS-2$
                    clName,
                    name,
                    desc,
                    opcode,
                    itf));
                this.log.debug("  Arguments " + args); //$NON-NLS-1$
                if ( realOpcode != Opcodes.INVOKESTATIC ) {
                    this.log.debug("  Target " + tgt); //$NON-NLS-1$
                }
            }
            this.parent.getAnalyzer().getState().traceCalls(r, Collections.singleton(this.ref));
            this.parent.getAnalyzer().getState().getBench().untaintedCall();
        }

        Type returnType = Type.getReturnType(desc);
        if ( returnType != Type.VOID_TYPE ) {
            boolean taintReturn = tainted;
            Type improvedReturnType = this.parent.getAnalyzer().getImprovedReturnType(r, fixedType, deserializedTarget);
            if ( improvedReturnType != null ) {
                if ( this.log.isDebugEnabled() ) {
                    this.log.debug("Method " + r + " has improved return type " + improvedReturnType); //$NON-NLS-1$ //$NON-NLS-2$
                }
                returnType = improvedReturnType;
            }

            if ( this.parent.getAnalyzer().getConfig().isUntaintReturn(r) ) {
                taintReturn = false;
            }
            else if ( !tainted && tgt instanceof BasicVariable ) {
                if ( this.log.isDebugEnabled() ) {
                    this.log.debug("Tainting return value for target " + tgt); //$NON-NLS-1$
                }
                taintReturn |= ( (BasicVariable) tgt ).isTaintReturns();
            }

            if ( taintReturn ) {
                this.parent.getAnalyzer().instantiable(r, returnType);
            }

            if ( this.log.isDebugEnabled() ) {
                this.log.debug("Return type " + returnType + ( taintReturn ? " <T>" : " <U>" )); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
            }
            this.stack.push(new BasicVariable(returnType, "return " + r, taintReturn)); //$NON-NLS-1$
        }

        super.visitMethodInsn(opcode, owner, name, desc, itf);
    }


    /**
     * @param v
     * @param args
     * @return
     */
    private boolean checkTainted ( Type[] formal, List<BaseType> args ) {
        boolean tainted = false;
        if ( args.size() < formal.length ) {
            this.log.trace("Not enough parameters"); //$NON-NLS-1$
            this.parent.getAnalyzer().getState().getBench().taintedByMissingArgs();
            return true;
        }
        for ( Object arg : args ) {
            if ( arg instanceof BaseType ) {
                tainted |= ( (BaseType) arg ).isTainted();
            }
            else {
                this.parent.getAnalyzer().getState().getBench().taintedByMissingArgs();
                return true;
            }
        }
        return tainted;
    }


    /**
     * @param opcode
     * @param args
     * @param tgt
     * @param r
     * @param signatureTypes
     * @return
     */
    private List<Type> setupTainting ( MethodReference call, int opcode, List<BaseType> args, Object tgt, MethodReference r, Type[] signatureTypes ) {
        if ( opcode != Opcodes.INVOKESTATIC && opcode != Opcodes.INVOKEDYNAMIC ) {
            if ( tgt == null || ! ( tgt instanceof BaseType ) || ( (BaseType) tgt ).isTainted() ) {
                r.taintCallee();
            }
        }

        boolean foundTypes = true;
        List<Type> actualTypes = new ArrayList<>();
        if ( signatureTypes.length != args.size() ) {
            return null;
        }
        for ( int i = 0; i < signatureTypes.length; i++ ) {
            Object object = args.get(i);
            if ( object instanceof BaseType ) {
                if ( object instanceof SimpleType ) {
                    Type type = ( (SimpleType) object ).getType();
                    Set<Type> altTypes = ( (BaseType) object ).getAlternativeTypes();

                    Type sigType = signatureTypes[ i ];
                    if ( type == null ) {
                        actualTypes.add(sigType);
                    }
                    else if ( altTypes == null || altTypes.isEmpty() ) {
                        try {
                            Type moreConcreteType = this.parent.getAnalyzer().getMoreConcreteType(type, sigType);
                            if ( !moreConcreteType.equals(sigType) ) {
                                // log.info("Improving type to " + moreConcreteType + " for " + call + " in " +
                                // this.ref);
                            }
                            actualTypes.add(moreConcreteType);
                        }
                        catch ( SerianalyzerException e ) {
                            this.log.error("Failed to determine argument type", e); //$NON-NLS-1$
                            this.log.warn("Formal arguments are " + Arrays.toString(signatureTypes)); //$NON-NLS-1$
                            this.log.warn("Known arguments are " + args); //$NON-NLS-1$
                            this.log.warn("Failing arg " + i + ": " + object); //$NON-NLS-1$ //$NON-NLS-2$
                            this.log.warn("Failing arg type " + type); //$NON-NLS-1$
                            this.log.warn("Signature type " + sigType); //$NON-NLS-1$
                            this.log.warn("In " + this.ref); //$NON-NLS-1$
                            this.log.warn("Calling " + call); //$NON-NLS-1$
                            foundTypes = false;
                        }
                    }
                }
                else {
                    foundTypes = false;
                }

                if ( ( (BaseType) object ).isTainted() ) {
                    r.taintParameter(i);
                }

                if ( object instanceof BasicVariable && ( (BasicVariable) object ).isTaintReturns() ) {
                    r.taintParameterReturns(i);
                }
            }
            else {
                r.taintParameter(i);
                foundTypes = false;
            }
        }

        if ( foundTypes ) {
            return actualTypes;
        }

        //
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitTypeInsn(int, java.lang.String)
     */
    @Override
    public void visitTypeInsn ( int opcode, String type ) {
        JVMImpl.handleJVMTypeInsn(opcode, type, this.stack);

        if ( opcode == Opcodes.NEW ) {
            String className = type.replace('/', '.');
            if ( this.log.isDebugEnabled() ) {
                this.log.debug("Found instantiation " + className); //$NON-NLS-1$
            }
            // if ( this.ref.isCalleeTainted() ) {
            this.parent.getAnalyzer().getState().trackInstantiable(className, this.ref, this.parent.getAnalyzer().getConfig(), false);
            // }
        }
        super.visitTypeInsn(opcode, type);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitMultiANewArrayInsn(java.lang.String, int)
     */
    @Override
    public void visitMultiANewArrayInsn ( String desc, int dims ) {
        JVMImpl.handleMultiANewArrayInsn(desc, dims, this.stack);
        super.visitMultiANewArrayInsn(desc, dims);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitLookupSwitchInsn(org.objectweb.asm.Label, int[],
     *      org.objectweb.asm.Label[])
     */
    @Override
    public void visitLookupSwitchInsn ( Label dflt, int[] keys, Label[] labels ) {
        this.stack.clear();
        super.visitLookupSwitchInsn(dflt, keys, labels);
    }


    /**
     * {@inheritDoc}
     *
     * @see org.objectweb.asm.MethodVisitor#visitEnd()
     */
    @Override
    public void visitEnd () {
        if ( !this.backwardJumpsToLabels.isEmpty() ) {
            boolean foundMultiAssigned = false;
            for ( Set<BaseType> set : this.stack.getVariables() ) {
                if ( set != null && set.size() > 1 ) {
                    foundMultiAssigned = true;
                    break;
                }
            }
            if ( foundMultiAssigned ) {
                this.parent.getAnalyzer().getState().getBench().backwardJump();
                if ( this.log.isDebugEnabled() ) {
                    this.log.debug("Found backward jumps to " + this.backwardJumpsToLabels + " in " + this.ref); //$NON-NLS-1$ //$NON-NLS-2$
                }
                for ( MethodReference r : this.foundRefs ) {
                    MethodReference fullTaint = r.fullTaint();
                    if ( !fullTaint.equals(r) ) {
                        this.parent.getAnalyzer().checkMethodCall(fullTaint, Collections.singleton(this.ref), false, false);
                    }
                }
            }
            return;
        }

        if ( !this.foundCall ) {
            if ( this.log.isDebugEnabled() ) {
                this.log.debug("Marking safe " + this.ref); //$NON-NLS-1$
            }

            this.parent.getAnalyzer().getState().markSafe(this.ref);
        }
        else if ( this.log.isTraceEnabled() ) {
            this.log.trace("Is not safe " + this.ref); //$NON-NLS-1$
        }

        Type sigType = Type.getReturnType(this.ref.getSignature());
        if ( !this.returnTypes.isEmpty() && this.ref.getArgumentTypes() == null ) {

            if ( this.returnTypes.size() == 1 ) {
                Type t = this.returnTypes.iterator().next();
                if ( !"Ljava/lang/Object;".equals(t.toString()) && !t.equals(sigType) ) { //$NON-NLS-1$
                    if ( this.log.isDebugEnabled() ) {
                        this.log.debug("Improving return type to " + t); //$NON-NLS-1$
                    }
                    try {
                        this.parent.getAnalyzer().foundImprovedReturnType(this.ref, t, sigType);
                    }
                    catch ( SerianalyzerException e ) {
                        this.log.error("Failed to determine return type", e); //$NON-NLS-1$
                        this.log.warn("Failing type " + t); //$NON-NLS-1$
                        this.log.warn("Signature type " + sigType); //$NON-NLS-1$
                        this.log.warn("For " + this.ref); //$NON-NLS-1$
                    }
                }
            }
            else if ( !this.returnTypes.contains(sigType) && this.log.isDebugEnabled() ) {
                this.log.debug("Found multiple return types ?!? " + this.returnTypes + " signature type is " + sigType); //$NON-NLS-1$ //$NON-NLS-2$
            }
        }

        this.parent.getAnalyzer().getState().foundReturnType(this.ref, sigType);
    }
}
